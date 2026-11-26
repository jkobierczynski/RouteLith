//! The alert engine (architecture doc §12, §21.5 F1–F4).
//!
//! The server feeds it every stored round; it keeps, per series and rule,
//! whether the alert is active, the streaks a threshold rule counts, and
//! the newest rounds a pattern needs, and answers with the alerts raised
//! and cleared by that round. It does no I/O: the caller writes the
//! transitions to the event log and rebuilds the state from it at start-up.
//!
//! A rule with `min_vantages = N > 1` (§21.7 G13) still runs per series,
//! but its per-series state only says whether that vantage matches: one
//! alert per target, family and rule is raised when N or more vantages
//! that count (connected agents and the server) match at once, and
//! cleared when fewer do. It is reported under the lowest series id of
//! the target and family, with the vantages that matched.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};

use rl_core::alert::{
    AlertRule, Baseline, BaselineStat, Comparison, Metric, Pattern, PatternValue, RuleKind,
    Threshold, eval,
};
use rl_store::{Event, EventKind};

/// What a rule sees of one round.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct RoundValues {
    /// Round start, Unix milliseconds.
    pub ts_ms: i64,
    pub sent: u32,
    pub received: u32,
    pub min_us: Option<u32>,
    /// Mean of the two middle RTTs for an even count, as SmokePing does.
    pub median_us: Option<u32>,
    /// 90th percentile, nearest rank.
    pub p90_us: Option<u32>,
    pub max_us: Option<u32>,
}

impl RoundValues {
    /// From a round's RTTs in ascending order.
    pub fn from_sorted(ts_ms: i64, sent: u32, rtts_us: &[u32]) -> Self {
        let n = rtts_us.len();
        let median_us = match n {
            0 => None,
            _ if n % 2 == 1 => Some(rtts_us[n / 2]),
            _ => {
                let sum = u64::from(rtts_us[n / 2 - 1]) + u64::from(rtts_us[n / 2]);
                u32::try_from(sum / 2).ok()
            }
        };
        let p90_us = (n > 0).then(|| rtts_us[(90 * n).div_ceil(100).max(1) - 1]);
        Self {
            ts_ms,
            sent,
            received: u32::try_from(n).unwrap_or(u32::MAX).min(sent),
            min_us: rtts_us.first().copied(),
            median_us,
            p90_us,
            max_us: rtts_us.last().copied(),
        }
    }

    fn lost(&self) -> u32 {
        self.sent.saturating_sub(self.received)
    }

    /// Loss in percent; `None` for a round that sent nothing.
    fn loss_pct(&self) -> Option<f64> {
        (self.sent > 0).then(|| 100.0 * f64::from(self.lost()) / f64::from(self.sent))
    }

    /// A metric's value in its rule unit: ms, percent or MOS.
    pub fn metric(&self, m: Metric) -> Option<f64> {
        let ms = |us: Option<u32>| us.map(|v| f64::from(v) / 1e3);
        match m {
            Metric::Median => ms(self.median_us),
            Metric::Min => ms(self.min_us),
            Metric::Max => ms(self.max_us),
            Metric::P90 => ms(self.p90_us),
            Metric::Loss => self.loss_pct(),
            Metric::Mos => {
                let loss = self.loss_pct()? / 100.0;
                rl_core::mos::round_mos(self.min_us?, self.median_us?, self.p90_us?, loss)
            }
        }
    }

    fn pattern_value(&self) -> PatternValue {
        PatternValue {
            loss_pct: self.loss_pct().unwrap_or(0.0),
            lost: self.lost(),
            median_ms: self.metric(Metric::Median),
        }
    }
}

/// An alert that is raised now.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveAlert {
    pub series: u64,
    pub rule: String,
    /// When the degradation began: the first round of the streak that
    /// raised it, or the round that completed the pattern.
    pub since_ms: i64,
    /// The value that raised it, in the rule's unit.
    pub value: Option<f64>,
    /// The silence it was raised under (§21.5 F6); set by the caller.
    pub silenced_by: Option<String>,
    /// The parent target that had an alert when it was raised; set by
    /// the caller.
    pub suppressed_by: Option<String>,
    /// For a rule with `min_vantages` > 1: the vantages that matched when
    /// it was raised. Empty otherwise.
    pub vantages: Vec<String>,
}

/// An alert raised or cleared by a round.
#[derive(Debug, Clone, PartialEq)]
pub struct Transition {
    pub raised: bool,
    pub series: u64,
    pub rule: String,
    /// The round that raised or cleared it.
    pub ts_ms: i64,
    /// When the degradation began (as [`ActiveAlert::since_ms`]).
    pub since_ms: i64,
    pub value: Option<f64>,
    /// What happened, for people, without the target's name.
    pub message: String,
    /// For a rule with `min_vantages` > 1: the vantages that match (on a
    /// raise) or still match (on a clear). Empty otherwise.
    pub vantages: Vec<String>,
}

#[derive(Debug, Clone)]
struct RuleState {
    rule: usize,
    /// Since when and with which value, while raised.
    active: Option<(i64, Option<f64>)>,
    /// Rounds in a row that met the condition, and when the run began.
    raise_streak: u32,
    streak_start: i64,
    /// Rounds in a row that met the clear test.
    clear_streak: u32,
    /// Newest rounds, oldest first, for a pattern rule.
    history: VecDeque<PatternValue>,
    /// Whether a round was evaluated since the start.
    observed: bool,
}

/// One alert over the vantages measuring a target and family, for a rule
/// with `min_vantages` > 1.
#[derive(Debug, Clone)]
struct Group {
    rule: usize,
    /// Series ids, ascending; the first one reports the alert.
    members: Vec<u64>,
    /// Since when, with which value and vantages, while raised.
    active: Option<(i64, Option<f64>, Vec<String>)>,
}

/// Every rule's state for every series it applies to.
#[derive(Debug)]
pub struct Engine {
    rules: Vec<AlertRule>,
    series: HashMap<u64, Vec<RuleState>>,
    /// Known baselines per series, by metric and baseline (§21.5 F5).
    baselines: HashMap<u64, HashMap<(Metric, Baseline), f64>>,
    /// Correlated alerts (G13), and the group of each series and rule.
    groups: Vec<Group>,
    group_of: HashMap<(u64, usize), usize>,
    /// Each series' vantage name, for messages.
    vantage: HashMap<u64, String>,
    /// Until then (Unix ms), a correlated alert is not cleared while a
    /// vantage has sent no round since the start: after a restart, its
    /// agent may not have reconnected yet.
    settle_until_ms: i64,
}

const HOUR_MS: i64 = 3_600_000;

impl Engine {
    /// `assign` lists, per series, the names of the rules that apply to
    /// it; names without a rule are ignored (the configuration rejects them).
    pub fn new(
        rules: Vec<AlertRule>,
        assign: impl IntoIterator<Item = (u64, Vec<String>)>,
    ) -> Self {
        let mut series = HashMap::new();
        for (id, names) in assign {
            let states: Vec<RuleState> = names
                .iter()
                .filter_map(|n| rules.iter().position(|r| &r.name == n))
                .map(|rule| RuleState {
                    rule,
                    active: None,
                    raise_streak: 0,
                    streak_start: 0,
                    clear_streak: 0,
                    history: VecDeque::new(),
                    observed: false,
                })
                .collect();
            if !states.is_empty() {
                series.insert(id, states);
            }
        }
        Self {
            rules,
            series,
            baselines: HashMap::new(),
            groups: Vec::new(),
            group_of: HashMap::new(),
            vantage: HashMap::new(),
            settle_until_ms: 0,
        }
    }

    /// Say which series measure the same target and family (`key`) from
    /// which vantage, for rules with `min_vantages` > 1.
    pub fn set_groups<K: std::hash::Hash + Eq + Clone>(
        &mut self,
        series: impl IntoIterator<Item = (u64, K, String)>,
    ) {
        let mut by_key: HashMap<(K, usize), Vec<u64>> = HashMap::new();
        for (id, key, vantage) in series {
            self.vantage.insert(id, vantage);
            let Some(states) = self.series.get(&id) else {
                continue;
            };
            for st in states {
                if self.rules[st.rule].min_vantages > 1 {
                    by_key.entry((key.clone(), st.rule)).or_default().push(id);
                }
            }
        }
        let mut groups: Vec<Group> = by_key
            .into_iter()
            .map(|((_, rule), mut members)| {
                members.sort_unstable();
                Group {
                    rule,
                    members,
                    active: None,
                }
            })
            .collect();
        groups.sort_by_key(|g| (g.members[0], g.rule));
        self.group_of.clear();
        for (i, g) in groups.iter().enumerate() {
            for &m in &g.members {
                self.group_of.insert((m, g.rule), i);
            }
        }
        self.groups = groups;
    }

    /// Whether `rule` needs more than one vantage.
    pub fn correlated(&self, rule: &str) -> bool {
        self.rules
            .iter()
            .any(|r| r.name == rule && r.min_vantages > 1)
    }

    /// Hold back clearing correlated alerts until `t_ms` while a vantage
    /// has not reported since the start (see the field).
    pub fn settle_until(&mut self, t_ms: i64) {
        self.settle_until_ms = t_ms;
    }

    /// Correlated rules a target can never raise, as fewer vantages
    /// measure it than the rule needs: (rule, reporting series, vantages).
    pub fn unreachable_groups(&self) -> Vec<(String, u64, usize)> {
        self.groups
            .iter()
            .filter(|g| g.members.len() < self.rules[g.rule].min_vantages as usize)
            .map(|g| {
                (
                    self.rules[g.rule].name.clone(),
                    g.members[0],
                    g.members.len(),
                )
            })
            .collect()
    }

    /// The metrics and baselines the rules of `series` use; empty when
    /// none of them uses a baseline.
    pub fn baselines_used(&self, series: u64) -> Vec<(Metric, Baseline)> {
        let mut out: Vec<(Metric, Baseline)> = self
            .series
            .get(&series)
            .into_iter()
            .flatten()
            .filter_map(|st| match &self.rules[st.rule].kind {
                RuleKind::Threshold(t) => Some(t.baselines().into_iter().map(|b| (t.metric, b))),
                RuleKind::Pattern(_) => None,
            })
            .flatten()
            .collect();
        out.sort_by_key(|(m, b)| (m.as_str(), *b));
        out.dedup();
        out
    }

    /// Recompute the baselines of `series` from its hourly values (one
    /// [`RoundValues`] per hour, any order). Each covers the whole hours of
    /// its window before the hour of `now_ms`, and stays unknown until the
    /// window holds [`Baseline::min_hours`] values.
    pub fn set_hourly(&mut self, series: u64, hourly: &[RoundValues], now_ms: i64) {
        let hour = now_ms - now_ms.rem_euclid(HOUR_MS);
        let mut known = HashMap::new();
        for (metric, b) in self.baselines_used(series) {
            let from = hour - i64::from(b.days) * 24 * HOUR_MS;
            let mut v: Vec<f64> = hourly
                .iter()
                .filter(|r| r.ts_ms >= from && r.ts_ms < hour)
                .filter_map(|r| r.metric(metric))
                .collect();
            if v.len() < b.min_hours() {
                continue;
            }
            v.sort_by(f64::total_cmp);
            known.insert((metric, b), stat(&v, b.stat));
        }
        self.baselines.insert(series, known);
    }

    /// A baseline of `series` for `metric`, if known.
    pub fn baseline(&self, series: u64, metric: Metric, b: Baseline) -> Option<f64> {
        self.baselines.get(&series)?.get(&(metric, b)).copied()
    }

    pub fn rules(&self) -> &[AlertRule] {
        &self.rules
    }

    /// Whether `rule` applies to `series`.
    pub fn applies(&self, series: u64, rule: &str) -> bool {
        self.state(series, rule).is_some()
    }

    fn state(&self, series: u64, rule: &str) -> Option<&RuleState> {
        self.series
            .get(&series)?
            .iter()
            .find(|s| self.rules[s.rule].name == rule)
    }

    /// Mark an alert active again after a restart. Returns `false` if the
    /// rule no longer applies to the series.
    pub fn restore(&mut self, series: u64, rule: &str, since_ms: i64, value: Option<f64>) -> bool {
        self.restore_with(series, rule, since_ms, value, Vec::new())
    }

    /// As [`restore`](Self::restore), with the vantages a correlated alert
    /// was raised from. A correlated alert comes back only under the
    /// series that reports it (the lowest id of its target and family).
    pub fn restore_with(
        &mut self,
        series: u64,
        rule: &str,
        since_ms: i64,
        value: Option<f64>,
        vantages: Vec<String>,
    ) -> bool {
        let Some(ri) = self.rules.iter().position(|r| r.name == rule) else {
            return false;
        };
        if self.rules[ri].min_vantages > 1 {
            return match self.group_of.get(&(series, ri)) {
                Some(&g) if self.groups[g].members[0] == series => {
                    // The vantages that matched match again, until their
                    // own rounds clear them.
                    for &m in &self.groups[g].members {
                        let matched = self.vantage.get(&m).is_some_and(|v| vantages.contains(v));
                        let st = self
                            .series
                            .get_mut(&m)
                            .and_then(|v| v.iter_mut().find(|s| s.rule == ri));
                        if let (true, Some(st)) = (matched, st) {
                            st.active = Some((since_ms, value));
                        }
                    }
                    self.groups[g].active = Some((since_ms, value, vantages));
                    true
                }
                _ => false,
            };
        }
        let rules = &self.rules;
        let Some(st) = self
            .series
            .get_mut(&series)
            .and_then(|v| v.iter_mut().find(|s| rules[s.rule].name == rule))
        else {
            return false;
        };
        st.active = Some((since_ms, value));
        st.clear_streak = 0;
        true
    }

    /// Feed an older round to fill the pattern history, without raising or
    /// clearing anything (used at start-up with the newest stored rounds).
    pub fn warm(&mut self, series: u64, r: &RoundValues) {
        let Some(states) = self.series.get_mut(&series) else {
            return;
        };
        for st in states {
            if let RuleKind::Pattern(p) = &self.rules[st.rule].kind {
                push(&mut st.history, r.pattern_value(), p.window());
            }
        }
    }

    /// Evaluate a newly stored round of `series`, with every vantage
    /// counting.
    pub fn observe(&mut self, series: u64, r: &RoundValues) -> Vec<Transition> {
        self.observe_with(series, r, &|_| true)
    }

    /// Evaluate a newly stored round of `series`. `counts` says whether a
    /// series' vantage counts for correlated rules now (a disconnected
    /// agent does not).
    pub fn observe_with(
        &mut self,
        series: u64,
        r: &RoundValues,
        counts: &dyn Fn(u64) -> bool,
    ) -> Vec<Transition> {
        let mut out = Vec::new();
        let mut correlated = Vec::new();
        let Some(states) = self.series.get_mut(&series) else {
            return out;
        };
        let known = self.baselines.get(&series);
        for st in states {
            st.observed = true;
            let rule = &self.rules[st.rule];
            let t = match &rule.kind {
                RuleKind::Threshold(t) => {
                    let base = |b: Baseline| known?.get(&(t.metric, b)).copied();
                    threshold(st, t, r, &base)
                }
                RuleKind::Pattern(p) => pattern(st, p, r),
            };
            if rule.min_vantages > 1 {
                // Only whether this vantage matches; the group decides.
                correlated.push(st.rule);
                continue;
            }
            if let Some((raised, since_ms, value, what)) = t {
                let message = if raised {
                    format!("{} raised: {what}", rule.name)
                } else {
                    format!("{} cleared: {what}", rule.name)
                };
                out.push(Transition {
                    raised,
                    series,
                    rule: rule.name.clone(),
                    ts_ms: r.ts_ms,
                    since_ms,
                    value,
                    message,
                    vantages: Vec::new(),
                });
            }
        }
        for rule in correlated {
            out.extend(self.correlate(series, rule, r, counts));
        }
        out
    }

    /// Raise or clear the correlated alert of `series`' group for `rule`.
    fn correlate(
        &mut self,
        series: u64,
        rule: usize,
        r: &RoundValues,
        counts: &dyn Fn(u64) -> bool,
    ) -> Option<Transition> {
        let &g = self.group_of.get(&(series, rule))?;
        let need = self.rules[rule].min_vantages as usize;
        let members = &self.groups[g].members;
        let (mut matching, mut since, mut unsettled) = (Vec::new(), i64::MIN, false);
        for &m in members {
            let Some(st) = self
                .series
                .get(&m)
                .and_then(|v| v.iter().find(|s| s.rule == rule))
            else {
                continue;
            };
            // A vantage not heard from since the start may be an agent
            // that has not reconnected yet.
            unsettled |= !st.observed;
            if !counts(m) {
                continue;
            }
            if let Some((s, _)) = st.active {
                matching.push(m);
                since = since.max(s);
            }
        }
        let names: Vec<String> = matching
            .iter()
            .map(|m| {
                self.vantage
                    .get(m)
                    .cloned()
                    .unwrap_or_else(|| format!("series {m}"))
            })
            .collect();
        let (reporter, total) = (members[0], members.len());
        let name = self.rules[rule].name.clone();
        let value = rule_value(&self.rules[rule].kind, r);
        let settling = unsettled && r.ts_ms < self.settle_until_ms;
        let group = &mut self.groups[g];
        let (raised, since_ms, message) = match &group.active {
            None if matching.len() >= need => {
                group.active = Some((since, value, names.clone()));
                let message = format!(
                    "{name} raised: {} of {total} vantages match ({})",
                    matching.len(),
                    names.join(", ")
                );
                (true, since, message)
            }
            Some((since, _, _)) if matching.len() < need && !settling => {
                let since = *since;
                group.active = None;
                let message = format!(
                    "{name} cleared: {} of {total} vantages match, fewer than {need}",
                    matching.len()
                );
                (false, since, message)
            }
            _ => return None,
        };
        Some(Transition {
            raised,
            series: reporter,
            rule: name,
            ts_ms: r.ts_ms,
            since_ms,
            value,
            message,
            vantages: names,
        })
    }

    /// Alerts raised now, by series id then rule order.
    pub fn active(&self) -> Vec<ActiveAlert> {
        let mut out: Vec<ActiveAlert> = self
            .series
            .iter()
            .flat_map(|(&series, states)| {
                states
                    .iter()
                    .filter(|st| self.rules[st.rule].min_vantages <= 1)
                    .filter_map(move |st| {
                        st.active.map(|(since_ms, value)| ActiveAlert {
                            series,
                            rule: self.rules[st.rule].name.clone(),
                            since_ms,
                            value,
                            silenced_by: None,
                            suppressed_by: None,
                            vantages: Vec::new(),
                        })
                    })
            })
            .collect();
        for g in &self.groups {
            if let Some((since_ms, value, vantages)) = &g.active {
                out.push(ActiveAlert {
                    series: g.members[0],
                    rule: self.rules[g.rule].name.clone(),
                    since_ms: *since_ms,
                    value: *value,
                    silenced_by: None,
                    suppressed_by: None,
                    vantages: vantages.clone(),
                });
            }
        }
        out.sort_by(|a, b| (a.series, &a.rule).cmp(&(b.series, &b.rule)));
        out
    }
}

/// A round's value in a rule's unit, as a correlated alert reports it.
fn rule_value(kind: &RuleKind, r: &RoundValues) -> Option<f64> {
    match kind {
        RuleKind::Threshold(t) => r.metric(t.metric),
        RuleKind::Pattern(p) => match p.kind {
            rl_core::alert::PatternType::Loss => r.loss_pct(),
            rl_core::alert::PatternType::Rtt => r.metric(Metric::Median),
        },
    }
}

fn push(h: &mut VecDeque<PatternValue>, v: PatternValue, window: usize) {
    h.push_back(v);
    while h.len() > window {
        h.pop_front();
    }
}

type Change = (bool, i64, Option<f64>, String);

/// A statistic of values in ascending order (not empty).
fn stat(v: &[f64], s: BaselineStat) -> f64 {
    let n = v.len();
    match s {
        BaselineStat::Min => v[0],
        BaselineStat::Max => v[n - 1],
        // As a round's median: the mean of the middle two for an even count.
        BaselineStat::P50 if n % 2 == 0 => (v[n / 2 - 1] + v[n / 2]) / 2.0,
        BaselineStat::P50 => v[n / 2],
        // Nearest rank, as a round's p90.
        BaselineStat::P90 => v[(90 * n).div_ceil(100).max(1) - 1],
    }
}

fn threshold(
    st: &mut RuleState,
    t: &Threshold,
    r: &RoundValues,
    base: &dyn Fn(Baseline) -> Option<f64>,
) -> Option<Change> {
    let v = r.metric(t.metric);
    let shown = |v: Option<f64>| v.map_or_else(|| "no value".to_string(), |v| t.metric.format(v));
    match st.active {
        None => {
            if eval(&t.condition, v, base) == Some(true) {
                if st.raise_streak == 0 {
                    st.streak_start = r.ts_ms;
                }
                st.raise_streak += 1;
            } else {
                st.raise_streak = 0;
            }
            if st.raise_streak < t.for_rounds {
                return None;
            }
            st.active = Some((st.streak_start, v));
            st.clear_streak = 0;
            let rounds = if t.for_rounds == 1 {
                String::new()
            } else {
                format!(" for {} rounds", t.for_rounds)
            };
            let what = format!(
                "{} {} {}{rounds}",
                t.metric,
                shown(v),
                describe(&t.condition, t.metric, base)
            );
            Some((true, st.streak_start, v, what))
        }
        Some((since, _)) => {
            let clear = match &t.clear {
                Some(c) => eval(c, v, base) == Some(true),
                // Not met, and known: a round without a value, or while a
                // baseline is unknown, says nothing.
                None => eval(&t.condition, v, base) == Some(false),
            };
            st.clear_streak = if clear { st.clear_streak + 1 } else { 0 };
            if st.clear_streak < t.clear_rounds {
                return None;
            }
            st.active = None;
            st.raise_streak = 0;
            st.clear_streak = 0;
            Some((false, since, v, format!("{} {}", t.metric, shown(v))))
        }
    }
}

/// The condition as written, with the limit a baseline gave in brackets.
fn describe(cmps: &[Comparison], m: Metric, base: &dyn Fn(Baseline) -> Option<f64>) -> String {
    cmps.iter()
        .map(|c| match (c.baseline, c.limit_with(base)) {
            (Some(_), Some(limit)) => format!("{} (= {})", c.text(m), m.format(limit)),
            _ => c.text(m),
        })
        .collect::<Vec<_>>()
        .join(" and ")
}

fn pattern(st: &mut RuleState, p: &Pattern, r: &RoundValues) -> Option<Change> {
    let pv = r.pattern_value();
    push(&mut st.history, pv, p.window());
    let matched = p.matches(st.history.make_contiguous());
    let (value, shown) = match p.kind {
        rl_core::alert::PatternType::Loss => (
            Some(pv.loss_pct),
            format!("loss {}", Metric::Loss.format(pv.loss_pct)),
        ),
        rl_core::alert::PatternType::Rtt => (
            pv.median_ms,
            pv.median_ms.map_or_else(
                || "median: no reply".to_string(),
                |m| format!("median {}", Metric::Median.format(m)),
            ),
        ),
    };
    match (st.active, matched) {
        (None, true) => {
            st.active = Some((r.ts_ms, value));
            Some((
                true,
                r.ts_ms,
                value,
                format!("{} pattern matched ({shown})", p.kind.as_str()),
            ))
        }
        (Some((since, _)), false) => {
            st.active = None;
            Some((
                false,
                since,
                value,
                format!("{} pattern no longer matches ({shown})", p.kind.as_str()),
            ))
        }
        _ => None,
    }
}

/// Alerts the event log leaves raised: each series and rule whose last
/// alert event is a raise, with its start and value. `events` oldest first.
pub fn active_from_events(events: &[Event]) -> Vec<ActiveAlert> {
    let mut open: HashMap<(u64, String), &Event> = HashMap::new();
    for e in events {
        let (Some(series), Some(rule)) = (e.series, &e.rule) else {
            continue;
        };
        match e.kind {
            EventKind::AlertRaised => {
                open.insert((series, rule.clone()), e);
            }
            EventKind::AlertCleared => {
                open.remove(&(series, rule.clone()));
            }
            _ => {}
        }
    }
    let mut out: Vec<ActiveAlert> = open
        .into_iter()
        .map(|((series, rule), e)| ActiveAlert {
            series,
            rule,
            since_ms: e.since.unwrap_or(e.t),
            value: e.value,
            silenced_by: e.silenced_by.clone(),
            suppressed_by: e.suppressed_by.clone(),
            vantages: e.vantages.clone(),
        })
        .collect();
    out.sort_by(|a, b| (a.series, &a.rule).cmp(&(b.series, &b.rule)));
    out
}

#[cfg(test)]
mod tests;
