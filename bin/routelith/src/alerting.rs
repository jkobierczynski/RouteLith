//! Alerts in the server (architecture doc §12, §21.5 F1–F4): the rule
//! engine, fed by the store thread with every stored round, and the event
//! log it writes raised and cleared alerts, address changes and server
//! start and stop to.
//!
//! At start-up the alerts the last run left raised are read back from the
//! event log, and pattern rules get the newest stored rounds as history,
//! so a restart neither raises an alert twice nor forgets one. An alert
//! whose rule no longer applies to its series is cleared then.
//!
//! Baselines (F5) are computed from the hourly tier when the server starts
//! and again with each series' first round of a new hour. An alert raised
//! under a silence, or while the target's parent has an alert (F6), is
//! marked so in the event log, as is its clear: outputs leave both unsent.
//!
//! Every event is also handed to the outputs (F7: syslog, JSON lines),
//! which queue it and send it from their own threads.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rl_alert::{Engine, RoundValues, Transition, active_from_events};
use rl_core::alert::RuleKind;
use rl_core::config::Config;
use rl_core::silence::Silence;
use rl_store::{EVENT_DAYS, Event, EventKind, EventLog, Reader, SeriesKey, StoredRound, Tier};
use rl_web::{AlertBoard, RuleInfo};

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;
/// How long the outputs may take to deliver what is queued at stop.
const OUTPUT_GRACE: Duration = Duration::from_secs(5);

/// Why a raised alert is not sent: (silence, parent target).
type Quiet = (Option<String>, Option<String>);

/// One series as the alerts see it.
#[derive(Debug, Clone)]
pub(crate) struct SeriesAlerts {
    pub(crate) id: u64,
    pub(crate) key: SeriesKey,
    pub(crate) step_ms: u64,
    /// Names of the rules that apply.
    pub(crate) rules: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct Alerting {
    engine: Engine,
    log: EventLog,
    pub(crate) board: Arc<AlertBoard>,
    keys: HashMap<u64, SeriesKey>,
    vantage: String,
    /// The address each series measured last, to notice changes.
    last_ip: HashMap<u64, IpAddr>,
    /// Events that could not be written.
    pub(crate) write_errors: u64,
    last_error: Option<String>,
    data_dir: PathBuf,
    /// Opened on the first baseline refresh.
    reader: Option<Reader>,
    /// Start of the hour each series' baselines were last computed for.
    baseline_hour: HashMap<u64, i64>,
    silences: Vec<Silence>,
    /// Group and parent of each target.
    targets: HashMap<String, (String, Option<String>)>,
    /// Silence and parent of each raised alert, by series and rule.
    quiet: HashMap<(u64, String), Quiet>,
    pub(crate) outputs: rl_out::Outputs,
}

/// Build the engine and restore the last run's state.
pub(crate) fn start(
    cfg: &Config,
    series: &[SeriesAlerts],
    now_ms: i64,
) -> Result<Alerting, String> {
    let data_dir = &cfg.server.data_dir;
    let mut engine = Engine::new(
        cfg.alerts.clone(),
        series.iter().map(|s| (s.id, s.rules.clone())),
    );
    let rules = cfg
        .alerts
        .iter()
        .map(|r| RuleInfo {
            name: r.name.clone(),
            kind: r.kind_name().to_string(),
            summary: r.summary(),
            series: series
                .iter()
                .filter(|s| s.rules.contains(&r.name))
                .map(|s| s.id)
                .collect(),
        })
        .collect();
    let log = EventLog::open(data_dir, EVENT_DAYS)
        .map_err(|e| format!("cannot open the event log: {e}"))?;
    let outputs = rl_out::Outputs::start(
        &cfg.outputs,
        cfg.targets
            .iter()
            .map(|t| (t.id.clone(), t.group.clone()))
            .collect(),
        Some(crate::render::email_graph(data_dir.clone())),
    )?;
    let past = rl_store::read_events(data_dir, now_ms - (EVENT_DAYS + 1) * DAY_MS, i64::MAX)
        .map_err(|e| format!("cannot read the event log: {e}"))?;
    let mut a = Alerting {
        engine: Engine::new(Vec::new(), []),
        log,
        board: Arc::new(AlertBoard::new(rules).with_silences(cfg.silences.clone())),
        keys: series.iter().map(|s| (s.id, s.key.clone())).collect(),
        vantage: cfg.server.vantage.clone(),
        last_ip: HashMap::new(),
        write_errors: 0,
        last_error: None,
        data_dir: data_dir.clone(),
        reader: None,
        baseline_hour: HashMap::new(),
        silences: cfg.silences.clone(),
        targets: cfg
            .targets
            .iter()
            .map(|t| (t.id.clone(), (t.group.clone(), t.parent.clone())))
            .collect(),
        quiet: HashMap::new(),
        outputs,
    };

    // Alerts left raised: keep them, or clear those whose rule is gone.
    let mut stale = Vec::new();
    for active in active_from_events(&past) {
        if engine.restore(active.series, &active.rule, active.since_ms, active.value) {
            a.quiet.insert(
                (active.series, active.rule.clone()),
                (active.silenced_by.clone(), active.suppressed_by.clone()),
            );
        } else {
            stale.push(active);
        }
    }
    for s in stale {
        // The raise names the target even if the series is gone now.
        let raised = past.iter().rev().find(|e| {
            e.kind == EventKind::AlertRaised
                && e.series == Some(s.series)
                && e.rule.as_deref() == Some(s.rule.as_str())
        });
        let mut e = Event::new(
            now_ms,
            EventKind::AlertCleared,
            &cfg.server.vantage,
            String::new(),
        );
        e.series = Some(s.series);
        e.rule = Some(s.rule.clone());
        e.since = Some(s.since_ms);
        e.target = raised.and_then(|r| r.target.clone());
        e.family = raised.and_then(|r| r.family.clone());
        e.silenced_by = s.silenced_by.clone();
        e.suppressed_by = s.suppressed_by.clone();
        e.message = format!(
            "{}{} cleared: the rule no longer applies (configuration changed)",
            subject(e.target.as_deref(), e.family.as_deref()),
            s.rule
        );
        a.record(e);
    }

    warm(&mut engine, data_dir, series, now_ms);
    a.engine = engine;
    for s in series {
        a.refresh_baselines(s.id, now_ms);
    }
    let active = a.active();
    let e = Event::new(
        now_ms,
        EventKind::ServerStarted,
        &cfg.server.vantage,
        format!(
            "server started: {} series, {} alert rule{}, {} alert{} still raised",
            series.len(),
            cfg.alerts.len(),
            if cfg.alerts.len() == 1 { "" } else { "s" },
            active.len(),
            if active.len() == 1 { "" } else { "s" },
        ),
    );
    a.record(e);
    a.board.set_active(active);
    Ok(a)
}

/// `" (silenced by x)"`, `" (suppressed: parent y has an alert)"`, or both.
fn quiet_note(q: &Quiet) -> String {
    let mut s = String::new();
    if let Some(name) = &q.0 {
        s += &format!(" (silenced by {name})");
    }
    if let Some(parent) = &q.1 {
        s += &format!(" (suppressed: parent {parent} has an alert)");
    }
    s
}

/// Give pattern rules the newest stored rounds as history.
fn warm(engine: &mut Engine, data_dir: &Path, series: &[SeriesAlerts], now_ms: i64) {
    let window = |s: &SeriesAlerts| {
        engine
            .rules()
            .iter()
            .filter(|r| s.rules.contains(&r.name))
            .filter_map(|r| match &r.kind {
                RuleKind::Pattern(p) => Some(p.window()),
                RuleKind::Threshold(_) => None,
            })
            .max()
    };
    let wanted: Vec<(&SeriesAlerts, usize)> = series
        .iter()
        .filter_map(|s| Some((s, window(s)?)))
        .collect();
    if wanted.is_empty() {
        return;
    }
    let reader = match Reader::open(data_dir) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("routelith server: warning: alert history not loaded: {e}");
            return;
        }
    };
    for (s, n) in wanted {
        let span = i64::try_from(s.step_ms.saturating_mul(n as u64 + 2)).unwrap_or(i64::MAX);
        match reader.read(s.id, now_ms.saturating_sub(span), now_ms) {
            Ok(rounds) => {
                for r in &rounds[rounds.len().saturating_sub(n)..] {
                    engine.warm(s.id, &values(r));
                }
            }
            Err(e) => {
                eprintln!(
                    "routelith server: warning: alert history of {} not loaded: {e}",
                    s.key
                );
            }
        }
    }
}

/// An hourly point as a round: its quantiles as the replies, with its
/// real sent and received counts (not the graph's scaled ones), so the
/// loss is exact.
fn hour_values(p: &rl_store::RollupPoint) -> RoundValues {
    let mut v = RoundValues::from_sorted(p.ts_ms, p.sent, &p.quantiles_us);
    v.received = p.received.min(p.sent);
    v
}

fn values(r: &StoredRound) -> RoundValues {
    RoundValues::from_sorted(r.ts_ms, u32::from(r.sent), &r.rtts_us)
}

/// `target (family): ` for messages.
fn subject(target: Option<&str>, family: Option<&str>) -> String {
    match (target, family) {
        (Some(t), Some(f)) => format!("{t} ({f}): "),
        (Some(t), None) => format!("{t}: "),
        _ => String::new(),
    }
}

impl Alerting {
    /// Evaluate a round the store has just written.
    pub(crate) fn round(&mut self, series: u64, r: &StoredRound) {
        self.refresh_baselines(series, r.ts_ms);
        let transitions = self.engine.observe(series, &values(r));
        if !transitions.is_empty() {
            for t in transitions {
                self.board.count(t.raised);
                let key = (t.series, t.rule.clone());
                let quiet = if t.raised {
                    let q = self.quiet_for(&t);
                    self.quiet.insert(key, q.clone());
                    q
                } else {
                    self.quiet.remove(&key).unwrap_or_default()
                };
                let e = self.alert_event(&t, &quiet);
                self.record(e);
            }
            self.board.set_active(self.active());
        }
        if let Some(ip) = r.resolved {
            if let Some(old) = self.last_ip.insert(series, ip) {
                if old != ip {
                    let mut e = self.series_event(series, r.ts_ms, EventKind::IpChanged);
                    e.from = Some(old.to_string());
                    e.to = Some(ip.to_string());
                    e.message = format!(
                        "{}address changed from {old} to {ip}",
                        subject(e.target.as_deref(), e.family.as_deref())
                    );
                    self.record(e);
                }
            }
        }
    }

    /// Active alerts with why each is not sent.
    fn active(&self) -> Vec<rl_alert::ActiveAlert> {
        let mut out = self.engine.active();
        for a in &mut out {
            if let Some((silence, parent)) = self.quiet.get(&(a.series, a.rule.clone())) {
                a.silenced_by.clone_from(silence);
                a.suppressed_by.clone_from(parent);
            }
        }
        out
    }

    /// The silence an alert is raised under, and the parent target that
    /// has an alert raised now.
    fn quiet_for(&self, t: &Transition) -> Quiet {
        let Some(key) = self.keys.get(&t.series) else {
            return (None, None);
        };
        let Some((group, parent)) = self.targets.get(&key.target) else {
            return (None, None);
        };
        let silence = self
            .silences
            .iter()
            .find(|s| s.applies(&key.target, group, &t.rule) && s.active_at(t.ts_ms))
            .map(|s| s.name.clone());
        let parent = parent.as_ref().filter(|p| {
            self.engine.active().iter().any(|a| {
                a.series != t.series && self.keys.get(&a.series).is_some_and(|k| &k.target == *p)
            })
        });
        (silence, parent.cloned())
    }

    /// Recompute the baselines of `series` once per hour, from its hourly
    /// points of the last 28 days. A read that fails leaves them unknown.
    fn refresh_baselines(&mut self, series: u64, now_ms: i64) {
        let used = self.engine.baselines_used(series);
        let Some(days) = used.iter().map(|(_, b)| b.days).max() else {
            return;
        };
        let hour = now_ms - now_ms.rem_euclid(HOUR_MS);
        if self.baseline_hour.get(&series).is_some_and(|&h| h >= hour) {
            return;
        }
        self.baseline_hour.insert(series, hour);
        if self.reader.is_none() {
            match Reader::open(&self.data_dir) {
                Ok(r) => self.reader = Some(r),
                Err(e) => {
                    eprintln!("routelith server: warning: baselines not computed: {e}");
                }
            }
        }
        let from = hour - i64::from(days) * 24 * HOUR_MS;
        let points = match &self.reader {
            Some(r) => r.read_tier(series, Tier::R1h, from, hour - 1),
            None => Ok(Vec::new()),
        };
        let hourly: Vec<RoundValues> = match points {
            Ok(p) => p.iter().map(hour_values).collect(),
            Err(e) => {
                eprintln!(
                    "routelith server: warning: baselines of series {series} not computed: {e}"
                );
                Vec::new()
            }
        };
        self.engine.set_hourly(series, &hourly, now_ms);
    }

    /// The store stopped cleanly: log it, and give the outputs a few
    /// seconds to deliver what they hold.
    pub(crate) fn stopped(&mut self, now_ms: i64) {
        let active = self.engine.active().len();
        let e = Event::new(
            now_ms,
            EventKind::ServerStopped,
            &self.vantage,
            format!(
                "server stopped with {active} alert{} raised",
                if active == 1 { "" } else { "s" }
            ),
        );
        self.record(e);
        std::mem::replace(&mut self.outputs, rl_out::Outputs::none()).close(OUTPUT_GRACE);
    }

    fn series_event(&self, series: u64, t: i64, kind: EventKind) -> Event {
        let mut e = Event::new(t, kind, &self.vantage, String::new());
        e.series = Some(series);
        if let Some(k) = self.keys.get(&series) {
            e.target = Some(k.target.clone());
            e.family = Some(k.family.clone());
        }
        e
    }

    fn alert_event(&self, t: &Transition, quiet: &Quiet) -> Event {
        let kind = if t.raised {
            EventKind::AlertRaised
        } else {
            EventKind::AlertCleared
        };
        let mut e = self.series_event(t.series, t.ts_ms, kind);
        e.rule = Some(t.rule.clone());
        e.value = t.value.map(|v| (v * 1000.0).round() / 1000.0);
        e.since = Some(t.since_ms);
        e.silenced_by.clone_from(&quiet.0);
        e.suppressed_by.clone_from(&quiet.1);
        e.message = format!(
            "{}{}{}",
            subject(e.target.as_deref(), e.family.as_deref()),
            t.message,
            quiet_note(quiet)
        );
        e
    }

    /// Write an event, say it on stderr and queue it for the outputs. A
    /// write that fails is counted and reported, but does not stop the
    /// store.
    fn record(&mut self, e: Event) {
        eprintln!("routelith server: event: {}", e.message);
        self.outputs.send(&e);
        if let Err(err) = self.log.append(&e) {
            self.write_errors += 1;
            let msg = err.to_string();
            if self.last_error.as_deref() != Some(msg.as_str()) {
                eprintln!("routelith server: cannot write the event log: {msg}");
                self.last_error = Some(msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000_000;
    const STEP: i64 = 60_000;

    fn config(dir: &Path, rules: &str) -> Config {
        let src = format!(
            "[server]\ndata_dir = {:?}\n{rules}\n[[group]]\nname = \"g\"\n[[group.target]]\nname = \"a\"\nhost = \"192.0.2.1\"\n",
            dir.display().to_string()
        );
        let p = rl_core::config::parse(&src);
        p.config.unwrap_or_else(|| panic!("{:?}", p.diagnostics))
    }

    const SLOW: &str = "[defaults]\nalerts = [\"slow\"]\n[[alert]]\nname = \"slow\"\nmetric = \"median\"\ncondition = \"> 20ms\"\n";

    fn series(rules: &[&str]) -> Vec<SeriesAlerts> {
        vec![SeriesAlerts {
            id: 1,
            key: SeriesKey::new("local", "a", "v4"),
            step_ms: 60_000,
            rules: rules.iter().map(|s| s.to_string()).collect(),
        }]
    }

    fn round(i: i64, ms: u32, ip: &str) -> StoredRound {
        StoredRound {
            ts_ms: T0 + i * STEP,
            sent: 4,
            rtts_us: vec![ms * 1000; 4],
            errors: rl_store::ErrorCounts::default(),
            resolved: Some(ip.parse().unwrap()),
            timing: None,
            flags: 0,
        }
    }

    fn kinds(dir: &Path) -> Vec<(EventKind, Option<String>)> {
        rl_store::read_events(dir, 0, i64::MAX)
            .unwrap()
            .into_iter()
            .map(|e| (e.kind, e.rule))
            .collect()
    }

    #[test]
    fn alerts_survive_a_restart_without_a_second_raise() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path(), SLOW);
        let mut a = start(&cfg, &series(&["slow"]), T0).unwrap();
        a.round(1, &round(1, 30, "192.0.2.1"));
        assert_eq!(a.board.active().len(), 1);
        // Killed: no stop event. The next run picks the alert up.
        drop(a);
        let mut a = start(&cfg, &series(&["slow"]), T0 + 2 * STEP).unwrap();
        assert_eq!(a.board.active().len(), 1);
        a.round(1, &round(3, 40, "192.0.2.1"));
        a.round(1, &round(4, 10, "192.0.2.9"));
        a.stopped(T0 + 5 * STEP);
        assert!(a.board.active().is_empty());
        assert_eq!(
            kinds(tmp.path()),
            [
                (EventKind::ServerStarted, None),
                (EventKind::AlertRaised, Some("slow".into())),
                (EventKind::ServerStarted, None),
                (EventKind::AlertCleared, Some("slow".into())),
                (EventKind::IpChanged, None),
                (EventKind::ServerStopped, None),
            ]
        );
        let events = rl_store::read_events(tmp.path(), 0, i64::MAX).unwrap();
        assert_eq!(events[1].message, "a (v4): slow raised: median 30ms > 20ms");
        assert_eq!(events[3].since, Some(T0 + STEP));
        assert_eq!(
            (events[4].from.as_deref(), events[4].to.as_deref()),
            (Some("192.0.2.1"), Some("192.0.2.9"))
        );
    }

    #[test]
    fn events_reach_the_outputs_except_silenced_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out.jsonl");
        let rules = format!(
            "{SLOW}[[alert]]\nname = \"fast\"\nmetric = \"median\"\ncondition = \"< 15ms\"\n\
             [[silence]]\nname = \"m\"\nalerts = [\"fast\"]\n\
             start = \"2020-01-01T00:00:00Z\"\nend = \"2099-01-01T00:00:00Z\"\n\
             [[output]]\nname = \"file\"\ntype = \"jsonl\"\npath = {:?}\n",
            out.display().to_string()
        );
        let mut cfg = config(tmp.path(), &rules);
        cfg.targets[0].alerts.push("fast".into());
        let mut a = start(&cfg, &series(&["slow", "fast"]), T0).unwrap();
        a.round(1, &round(1, 30, "192.0.2.1")); // slow raised
        a.round(1, &round(2, 10, "192.0.2.1")); // slow cleared, fast raised (silenced)
        a.stopped(T0 + 3 * STEP);
        let sent: Vec<(EventKind, Option<String>)> = std::fs::read_to_string(&out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Event>(l).unwrap())
            .map(|e| (e.kind, e.rule))
            .collect();
        assert_eq!(
            sent,
            [
                (EventKind::ServerStarted, None),
                (EventKind::AlertRaised, Some("slow".into())),
                (EventKind::AlertCleared, Some("slow".into())),
                (EventKind::ServerStopped, None),
            ]
        );
        // The event log has the silenced raise too.
        assert!(kinds(tmp.path()).contains(&(EventKind::AlertRaised, Some("fast".into()))));
    }

    #[test]
    fn a_removed_rule_clears_its_alert_at_start_up() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path(), SLOW);
        let mut a = start(&cfg, &series(&["slow"]), T0).unwrap();
        a.round(1, &round(1, 30, "192.0.2.1"));
        drop(a);
        let cfg = config(tmp.path(), "");
        let a = start(&cfg, &series(&[]), T0 + 2 * STEP).unwrap();
        assert!(a.board.active().is_empty());
        let events = rl_store::read_events(tmp.path(), 0, i64::MAX).unwrap();
        let cleared = &events[2];
        assert_eq!(cleared.kind, EventKind::AlertCleared);
        assert_eq!(cleared.target.as_deref(), Some("a"));
        assert_eq!(
            cleared.message,
            "a (v4): slow cleared: the rule no longer applies (configuration changed)"
        );
        assert_eq!(events[3].kind, EventKind::ServerStarted);
    }

    const TWO: &str = "[server]\ndata_dir = DIR\n[defaults]\nalerts = [\"slow\"]\n\
        [[alert]]\nname = \"slow\"\nmetric = \"median\"\ncondition = \"> 20ms\"\n\
        [[silence]]\nname = \"works\"\ntargets = [\"a\"]\nstart = \"2027-01-15T08:00:00Z\"\n\
        end = \"2027-01-15T09:00:00Z\"\n\
        [[group]]\nname = \"g\"\n[[group.target]]\nname = \"a\"\nhost = \"192.0.2.1\"\n\
        [[group.target]]\nname = \"b\"\nhost = \"192.0.2.2\"\nparent = \"a\"\n";

    fn two(dir: &Path) -> (Config, Vec<SeriesAlerts>) {
        let src = TWO.replace("DIR", &format!("{:?}", dir.display().to_string()));
        let p = rl_core::config::parse(&src);
        let cfg = p.config.unwrap_or_else(|| panic!("{:?}", p.diagnostics));
        let s = |id, t: &str| SeriesAlerts {
            id,
            key: SeriesKey::new("local", t, "v4"),
            step_ms: 60_000,
            rules: vec!["slow".into()],
        };
        (cfg, vec![s(1, "a"), s(2, "b")])
    }

    #[test]
    fn silences_and_parents_mark_alerts_not_to_send() {
        let tmp = tempfile::tempdir().unwrap();
        let (cfg, series) = two(tmp.path());
        // 2027-01-15T08:00:00Z, inside the silence.
        let t0 = T0;
        let at = |i: i64, ms: u32| StoredRound {
            ts_ms: t0 + i * STEP,
            ..round(0, ms, "192.0.2.1")
        };
        let mut a = start(&cfg, &series, t0).unwrap();
        a.round(1, &at(1, 30));
        // b fails while its parent a has an alert.
        a.round(2, &at(1, 30));
        let active = a.board.active();
        assert_eq!(active[0].silenced_by.as_deref(), Some("works"));
        assert_eq!(active[1].suppressed_by.as_deref(), Some("a"));
        assert_eq!(active[1].silenced_by, None, "the silence names a only");
        // A restart keeps the marks.
        drop(a);
        let mut a = start(&cfg, &series, t0 + 2 * STEP).unwrap();
        assert_eq!(a.board.active()[1].suppressed_by.as_deref(), Some("a"));
        // a clears; b raised again later is sent. The clears carry the marks.
        a.round(1, &at(3, 10));
        a.round(2, &at(3, 10));
        a.round(2, &at(4, 30));
        let events = rl_store::read_events(tmp.path(), 0, i64::MAX).unwrap();
        let alerts: Vec<_> = events
            .iter()
            .filter(|e| e.rule.is_some())
            .map(|e| {
                (
                    e.kind,
                    e.target.as_deref().unwrap(),
                    e.silenced_by.as_deref(),
                    e.suppressed_by.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            alerts,
            [
                (EventKind::AlertRaised, "a", Some("works"), None),
                (EventKind::AlertRaised, "b", None, Some("a")),
                (EventKind::AlertCleared, "a", Some("works"), None),
                (EventKind::AlertCleared, "b", None, Some("a")),
                (EventKind::AlertRaised, "b", None, None),
            ]
        );
        assert_eq!(
            events[1].message,
            "a (v4): slow raised: median 30ms > 20ms (silenced by works)"
        );
        assert_eq!(
            events[2].message,
            "b (v4): slow raised: median 30ms > 20ms (suppressed: parent a has an alert)"
        );
    }

    #[test]
    fn hourly_loss_uses_the_real_counts() {
        let p = rl_store::RollupPoint {
            ts_ms: T0,
            rounds: 60,
            sent: 1200,
            received: 1141,
            quantiles_us: (1..=rl_store::QUANTILES as u32).map(|i| i * 1000).collect(),
        };
        let v = hour_values(&p);
        let loss = v.metric(rl_core::alert::Metric::Loss).unwrap();
        assert!((loss - 100.0 * 59.0 / 1200.0).abs() < 1e-9, "{loss}");
        assert_eq!(v.min_us, Some(1000));
    }

    #[test]
    fn baselines_come_from_the_hourly_tier() {
        use rl_store::{Writer, WriterOptions};
        let tmp = tempfile::tempdir().unwrap();
        let rule = "[defaults]\nalerts = [\"above\"]\n[[alert]]\nname = \"above\"\n\
            metric = \"median\"\ncondition = \"> baseline_p50_1d * 2\"\n";
        let cfg = config(tmp.path(), rule);
        // 26 hours of 10 ms rounds every 10 minutes before T0.
        let start_ms = T0 - 26 * HOUR_MS;
        let (mut w, _) = Writer::open(tmp.path(), WriterOptions::default(), start_ms).unwrap();
        let key = SeriesKey::new("local", "a", "v4");
        let id = w.register(std::slice::from_ref(&key)).unwrap()[0];
        for i in 0..26 * 6 {
            let mut r = round(0, 10, "192.0.2.1");
            r.ts_ms = start_ms + i * 600_000;
            w.append(id, r).unwrap();
        }
        w.close().unwrap();
        let series = vec![SeriesAlerts {
            id,
            key,
            step_ms: 60_000,
            rules: vec!["above".into()],
        }];
        let mut a = start(&cfg, &series, T0).unwrap();
        a.round(id, &round(1, 15, "192.0.2.1"));
        assert!(a.board.active().is_empty());
        a.round(id, &round(2, 25, "192.0.2.1"));
        let events = rl_store::read_events(tmp.path(), 0, i64::MAX).unwrap();
        assert_eq!(
            events.last().unwrap().message,
            "a (v4): above raised: median 25ms > baseline_p50_1d * 2 (= 20ms)"
        );
        // Without enough history the rule cannot raise.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = config(tmp.path(), rule);
        let mut a = start(&cfg, &series, T0).unwrap();
        a.round(id, &round(1, 500, "192.0.2.1"));
        assert!(a.board.active().is_empty());
    }
}
