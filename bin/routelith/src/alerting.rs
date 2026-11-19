//! Alerts in the server (architecture doc §12, §21.5 F1–F4): the rule
//! engine, fed by the store thread with every stored round, and the event
//! log it writes raised and cleared alerts, address changes and server
//! start and stop to.
//!
//! At start-up the alerts the last run left raised are read back from the
//! event log, and pattern rules get the newest stored rounds as history,
//! so a restart neither raises an alert twice nor forgets one. An alert
//! whose rule no longer applies to its series is cleared then.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use rl_alert::{Engine, RoundValues, Transition, active_from_events};
use rl_core::alert::RuleKind;
use rl_core::config::Config;
use rl_store::{EVENT_DAYS, Event, EventKind, EventLog, Reader, SeriesKey, StoredRound};
use rl_web::{AlertBoard, RuleInfo};

const DAY_MS: i64 = 86_400_000;

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
    let past = rl_store::read_events(data_dir, now_ms - (EVENT_DAYS + 1) * DAY_MS, i64::MAX)
        .map_err(|e| format!("cannot read the event log: {e}"))?;
    let mut a = Alerting {
        engine: Engine::new(Vec::new(), []),
        log,
        board: Arc::new(AlertBoard::new(rules)),
        keys: series.iter().map(|s| (s.id, s.key.clone())).collect(),
        vantage: cfg.server.vantage.clone(),
        last_ip: HashMap::new(),
        write_errors: 0,
        last_error: None,
    };

    // Alerts left raised: keep them, or clear those whose rule is gone.
    let mut stale = Vec::new();
    for active in active_from_events(&past) {
        if !engine.restore(active.series, &active.rule, active.since_ms, active.value) {
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
        e.message = format!(
            "{}{} cleared: the rule no longer applies (configuration changed)",
            subject(e.target.as_deref(), e.family.as_deref()),
            s.rule
        );
        a.record(e);
    }

    warm(&mut engine, data_dir, series, now_ms);
    a.engine = engine;
    let active = a.engine.active();
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
        let transitions = self.engine.observe(series, &values(r));
        if !transitions.is_empty() {
            for t in transitions {
                self.board.count(t.raised);
                let e = self.alert_event(&t);
                self.record(e);
            }
            self.board.set_active(self.engine.active());
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

    /// The store stopped cleanly.
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

    fn alert_event(&self, t: &Transition) -> Event {
        let kind = if t.raised {
            EventKind::AlertRaised
        } else {
            EventKind::AlertCleared
        };
        let mut e = self.series_event(t.series, t.ts_ms, kind);
        e.rule = Some(t.rule.clone());
        e.value = t.value.map(|v| (v * 1000.0).round() / 1000.0);
        e.since = Some(t.since_ms);
        e.message = format!(
            "{}{}",
            subject(e.target.as_deref(), e.family.as_deref()),
            t.message
        );
        e
    }

    /// Write an event and say it on stderr. A write that fails is counted
    /// and reported, but does not stop the store.
    fn record(&mut self, e: Event) {
        eprintln!("routelith server: event: {}", e.message);
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
}
