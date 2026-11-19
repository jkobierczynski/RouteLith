//! The alert engine (architecture doc §12, §21.5 F1–F4).
//!
//! The server feeds it every stored round; it keeps, per series and rule,
//! whether the alert is active, the streaks a threshold rule counts, and
//! the newest rounds a pattern needs, and answers with the alerts raised
//! and cleared by that round. It does no I/O: the caller writes the
//! transitions to the event log and rebuilds the state from it at start-up.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};

use rl_core::alert::{AlertRule, Metric, Pattern, PatternValue, RuleKind, Threshold, all_hold};
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
}

/// Every rule's state for every series it applies to.
#[derive(Debug)]
pub struct Engine {
    rules: Vec<AlertRule>,
    series: HashMap<u64, Vec<RuleState>>,
}

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
                })
                .collect();
            if !states.is_empty() {
                series.insert(id, states);
            }
        }
        Self { rules, series }
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

    /// Evaluate a newly stored round of `series`.
    pub fn observe(&mut self, series: u64, r: &RoundValues) -> Vec<Transition> {
        let mut out = Vec::new();
        let Some(states) = self.series.get_mut(&series) else {
            return out;
        };
        for st in states {
            let rule = &self.rules[st.rule];
            let t = match &rule.kind {
                RuleKind::Threshold(t) => threshold(st, t, r),
                RuleKind::Pattern(p) => pattern(st, p, r),
            };
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
                });
            }
        }
        out
    }

    /// Alerts raised now, by series id then rule order.
    pub fn active(&self) -> Vec<ActiveAlert> {
        let mut out: Vec<ActiveAlert> = self
            .series
            .iter()
            .flat_map(|(&series, states)| {
                states.iter().filter_map(move |st| {
                    st.active.map(|(since_ms, value)| ActiveAlert {
                        series,
                        rule: self.rules[st.rule].name.clone(),
                        since_ms,
                        value,
                    })
                })
            })
            .collect();
        out.sort_by(|a, b| (a.series, &a.rule).cmp(&(b.series, &b.rule)));
        out
    }
}

fn push(h: &mut VecDeque<PatternValue>, v: PatternValue, window: usize) {
    h.push_back(v);
    while h.len() > window {
        h.pop_front();
    }
}

type Change = (bool, i64, Option<f64>, String);

fn threshold(st: &mut RuleState, t: &Threshold, r: &RoundValues) -> Option<Change> {
    let v = r.metric(t.metric);
    let shown = |v: Option<f64>| v.map_or_else(|| "no value".to_string(), |v| t.metric.format(v));
    match st.active {
        None => {
            if all_hold(&t.condition, v) {
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
                describe(&t.condition, t.metric)
            );
            Some((true, st.streak_start, v, what))
        }
        Some((since, _)) => {
            let clear = match &t.clear {
                Some(c) => all_hold(c, v),
                // Not met, and known: a round without a value says nothing.
                None => v.is_some() && !all_hold(&t.condition, v),
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

fn describe(cmps: &[rl_core::alert::Comparison], m: Metric) -> String {
    cmps.iter()
        .map(|c| format!("{} {}", c.op.as_str(), m.format(c.limit)))
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
    let mut open: HashMap<(u64, String), (i64, Option<f64>)> = HashMap::new();
    for e in events {
        let (Some(series), Some(rule)) = (e.series, &e.rule) else {
            continue;
        };
        match e.kind {
            EventKind::AlertRaised => {
                open.insert((series, rule.clone()), (e.since.unwrap_or(e.t), e.value));
            }
            EventKind::AlertCleared => {
                open.remove(&(series, rule.clone()));
            }
            _ => {}
        }
    }
    let mut out: Vec<ActiveAlert> = open
        .into_iter()
        .map(|((series, rule), (since_ms, value))| ActiveAlert {
            series,
            rule,
            since_ms,
            value,
        })
        .collect();
    out.sort_by(|a, b| (a.series, &a.rule).cmp(&(b.series, &b.rule)));
    out
}

#[cfg(test)]
mod tests;
