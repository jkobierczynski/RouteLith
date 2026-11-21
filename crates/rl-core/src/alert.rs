//! Alert rules (architecture doc §12, §21.5 F1–F3): what a rule says, and
//! the parsers for its condition and pattern strings. Evaluation lives in
//! `rl-alert`; the configuration parser checks rules with these functions.
//!
//! ```toml
//! [[alert]]
//! name      = "latency-degraded"
//! metric    = "median"
//! condition = "> 20ms"
//! for       = "3 rounds"
//! clear     = "< 15ms for 3 rounds"
//!
//! [[alert]]
//! name    = "loss-burst"
//! type    = "loss"
//! pattern = [">0%", "*3*", ">0%"]
//! ```

use std::fmt;

/// A validated alert rule.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertRule {
    pub name: String,
    pub kind: RuleKind,
    /// Line of the `[[alert]]` table, for messages.
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleKind {
    /// A metric compared with fixed values, with hysteresis.
    Threshold(Threshold),
    /// A SmokePing pattern over the newest rounds.
    Pattern(Pattern),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Threshold {
    pub metric: Metric,
    /// Every comparison must hold for a round to count.
    pub condition: Vec<Comparison>,
    /// Rounds in a row the condition must hold to raise the alert.
    pub for_rounds: u32,
    /// What clears it; `None` clears when the condition is false.
    pub clear: Option<Vec<Comparison>>,
    /// Rounds in a row the clear test must hold.
    pub clear_rounds: u32,
}

/// The value of a round that a threshold rule looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Metric {
    /// RTT quantiles, compared in milliseconds.
    Median,
    Min,
    Max,
    P90,
    /// Samples lost or failed, percent of those sent.
    Loss,
    /// Mean opinion score, 1 to 4.5 (§19.1).
    Mos,
}

impl Metric {
    pub const ALL: [Metric; 6] = [
        Metric::Median,
        Metric::Min,
        Metric::Max,
        Metric::P90,
        Metric::Loss,
        Metric::Mos,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Metric::Median => "median",
            Metric::Min => "min",
            Metric::Max => "max",
            Metric::P90 => "p90",
            Metric::Loss => "loss",
            Metric::Mos => "mos",
        }
    }

    pub fn parse(s: &str) -> Option<Metric> {
        Metric::ALL.into_iter().find(|m| m.as_str() == s)
    }

    fn unit(self) -> Unit {
        match self {
            Metric::Median | Metric::Min | Metric::Max | Metric::P90 => Unit::Time,
            Metric::Loss => Unit::Percent,
            Metric::Mos => Unit::Plain,
        }
    }

    /// The value with its unit, for messages.
    pub fn format(self, v: f64) -> String {
        match self.unit() {
            Unit::Time => format!("{}ms", trim(v)),
            Unit::Percent => format!("{}%", trim(v)),
            Unit::Plain | Unit::Count => trim(v),
        }
    }

    /// A configured limit with its unit, without rounding it away: a
    /// rule's text must show the value it is evaluated against.
    pub fn format_limit(self, v: f64) -> String {
        let s = exact(v);
        match self.unit() {
            Unit::Time => format!("{s}ms"),
            Unit::Percent => format!("{s}%"),
            Unit::Plain | Unit::Count => s,
        }
    }
}

impl fmt::Display for Metric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AlertRule {
    /// The rule in one line, as in the configuration.
    pub fn summary(&self) -> String {
        match &self.kind {
            RuleKind::Threshold(t) => {
                let cmps = |c: &[Comparison]| {
                    c.iter()
                        .map(|c| c.text(t.metric))
                        .collect::<Vec<_>>()
                        .join(" and ")
                };
                let rounds = |n: u32| {
                    if n == 1 {
                        String::new()
                    } else {
                        format!(" for {n} rounds")
                    }
                };
                let mut s = format!(
                    "{} {}{}",
                    t.metric,
                    cmps(&t.condition),
                    rounds(t.for_rounds)
                );
                match &t.clear {
                    Some(c) => {
                        s += &format!("; clear {}{}", cmps(c), rounds(t.clear_rounds));
                    }
                    None if t.clear_rounds > 1 => {
                        s += &format!("; clears after {} rounds not met", t.clear_rounds);
                    }
                    None => {}
                }
                s
            }
            RuleKind::Pattern(p) => {
                let items: Vec<String> = p
                    .items
                    .iter()
                    .map(|i| match i {
                        PatternItem::Compare(c) if p.kind == PatternType::Loss => {
                            format!("{}{}%", c.op.as_str(), exact(c.limit))
                        }
                        PatternItem::Compare(c) | PatternItem::Count(c) => {
                            format!("{}{}", c.op.as_str(), exact(c.limit))
                        }
                        PatternItem::Unknown => "U".to_string(),
                        PatternItem::Any(n) => format!("*{n}*"),
                    })
                    .collect();
                format!("{} pattern {}", p.kind.as_str(), items.join(" "))
            }
        }
    }

    /// `threshold` or `pattern`.
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            RuleKind::Threshold(_) => "threshold",
            RuleKind::Pattern(_) => "pattern",
        }
    }
}

/// A number without trailing zeros, at most three decimals.
fn trim(v: f64) -> String {
    let s = format!("{v:.3}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// A number as written: Rust's shortest form that reads back the same.
fn exact(v: f64) -> String {
    format!("{v}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Gt => ">",
            Op::Ge => ">=",
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Eq => "==",
        }
    }

    pub fn holds(self, left: f64, right: f64) -> bool {
        match self {
            Op::Gt => left > right,
            Op::Ge => left >= right,
            Op::Lt => left < right,
            Op::Le => left <= right,
            Op::Eq => (left - right).abs() < 1e-9,
        }
    }
}

/// `value op limit`, the limit in the metric's unit (ms, percent, plain),
/// optionally plus a multiple of a baseline (§21.5 F5):
/// `value op factor × baseline + limit`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Comparison {
    pub op: Op,
    pub limit: f64,
    pub baseline: Option<BaselineTerm>,
}

/// `factor × baseline` in a comparison.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BaselineTerm {
    pub baseline: Baseline,
    pub factor: f64,
}

impl Comparison {
    /// A comparison with a fixed limit.
    pub fn fixed(op: Op, limit: f64) -> Self {
        Self {
            op,
            limit,
            baseline: None,
        }
    }

    /// Against a fixed limit; a comparison with a baseline never holds
    /// here (patterns and tests only use fixed limits).
    pub fn holds(&self, value: f64) -> bool {
        self.baseline.is_none() && self.op.holds(value, self.limit)
    }

    /// The limit in force, given the series' baselines; `None` while the
    /// baseline it needs is unknown.
    pub fn limit_with(&self, baselines: &dyn Fn(Baseline) -> Option<f64>) -> Option<f64> {
        match self.baseline {
            None => Some(self.limit),
            Some(t) => Some(t.factor * baselines(t.baseline)? + self.limit),
        }
    }

    /// The comparison as written in a condition, `op` first.
    pub fn text(&self, metric: Metric) -> String {
        let Some(t) = self.baseline else {
            return format!("{} {}", self.op.as_str(), metric.format_limit(self.limit));
        };
        let mut s = format!("{} {}", self.op.as_str(), t.baseline.name());
        if t.factor != 1.0 {
            s += &format!(" * {}", exact(t.factor));
        }
        if self.limit > 0.0 {
            s += &format!(" + {}", metric.format_limit(self.limit));
        } else if self.limit < 0.0 {
            s += &format!(" - {}", metric.format_limit(-self.limit));
        }
        s
    }
}

/// Every comparison holds for `value`; an unknown value never matches.
/// Fixed limits only (see [`eval`] for baselines).
pub fn all_hold(cmps: &[Comparison], value: Option<f64>) -> bool {
    eval(cmps, value, &|_| None) == Some(true)
}

/// Whether every comparison holds for `value`, or `None` when that cannot
/// be told: the value is unknown, or a baseline it needs is.
pub fn eval(
    cmps: &[Comparison],
    value: Option<f64>,
    baselines: &dyn Fn(Baseline) -> Option<f64>,
) -> Option<bool> {
    let v = value?;
    let mut all = true;
    for c in cmps {
        all &= c.op.holds(v, c.limit_with(baselines)?);
    }
    Some(all)
}

/// What a baseline summarises: the rule's metric per hour, over a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BaselineStat {
    P50,
    P90,
    Min,
    Max,
}

impl BaselineStat {
    pub const ALL: [BaselineStat; 4] = [Self::P50, Self::P90, Self::Min, Self::Max];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::P50 => "p50",
            Self::P90 => "p90",
            Self::Min => "min",
            Self::Max => "max",
        }
    }
}

/// `baseline_<stat>_<window>` (§21.5 F5): a statistic of the hourly values
/// of a rule's metric over the last 1, 7 or 28 days, as in
/// `baseline_p50_7d`, the median of the last week's hourly medians.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Baseline {
    pub stat: BaselineStat,
    pub days: u32,
}

impl Baseline {
    /// Windows a baseline can cover.
    pub const DAYS: [u32; 3] = [1, 7, 28];

    pub fn name(self) -> String {
        format!("baseline_{}_{}d", self.stat.as_str(), self.days)
    }

    pub fn parse(s: &str) -> Option<Baseline> {
        let rest = s.strip_prefix("baseline_")?;
        let (stat, days) = rest.split_once('_')?;
        let stat = BaselineStat::ALL.into_iter().find(|b| b.as_str() == stat)?;
        let days: u32 = days.strip_suffix('d')?.parse().ok()?;
        Self::DAYS
            .contains(&days)
            .then_some(Baseline { stat, days })
    }

    /// Hourly values the window must hold before the baseline is known:
    /// a day's worth, or 18 of the 24 hours of a one-day window.
    pub fn min_hours(self) -> usize {
        if self.days == 1 { 18 } else { 24 }
    }
}

impl Threshold {
    /// The baselines its condition and clear test use.
    pub fn baselines(&self) -> Vec<Baseline> {
        let mut out: Vec<Baseline> = self
            .condition
            .iter()
            .chain(self.clear.iter().flatten())
            .filter_map(|c| c.baseline.map(|t| t.baseline))
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// What a SmokePing pattern compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternType {
    /// Loss: percent (`>10%`) or a count of lost samples (`>3`).
    Loss,
    /// The round's median RTT in milliseconds.
    Rtt,
}

impl PatternType {
    pub fn as_str(self) -> &'static str {
        match self {
            PatternType::Loss => "loss",
            PatternType::Rtt => "rtt",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    pub kind: PatternType,
    pub items: Vec<PatternItem>,
}

impl Pattern {
    /// Rounds of history that can take part in a match.
    pub fn window(&self) -> usize {
        self.items
            .iter()
            .map(|i| match i {
                PatternItem::Any(n) => *n as usize,
                _ => 1,
            })
            .sum()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PatternItem {
    /// Loss in percent, or the median in ms.
    Compare(Comparison),
    /// Loss as a count of lost samples (a loss value without `%`).
    Count(Comparison),
    /// `U`: the round has no value (no reply, so no median).
    Unknown,
    /// `*N*`: up to N rounds of anything.
    Any(u32),
}

/// Units a value can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    /// `us`, `ms` or `s`, kept in milliseconds.
    Time,
    Percent,
    Plain,
    /// A plain whole number of samples (loss patterns).
    Count,
}

/// Split a leading comparison operator off `s`.
fn split_op(s: &str) -> Option<(Op, &str)> {
    for (text, op) in [
        (">=", Op::Ge),
        ("<=", Op::Le),
        ("==", Op::Eq),
        (">", Op::Gt),
        ("<", Op::Lt),
    ] {
        if let Some(rest) = s.strip_prefix(text) {
            return Some((op, rest.trim_start()));
        }
    }
    None
}

/// A plain non-negative decimal number.
fn number(s: &str) -> Option<f64> {
    let ok = !s.is_empty()
        && s != "."
        && s.bytes().filter(|&b| b == b'.').count() <= 1
        && s.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    ok.then(|| s.parse().ok()).flatten()
}

/// A value with the unit a metric of `unit` takes, in that unit
/// (milliseconds for times).
fn value(rest: &str, unit: Unit, what: &str) -> Result<f64, String> {
    let rest = rest.trim();
    let split = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    let (num, suffix) = rest.split_at(split);
    let value = number(num).ok_or_else(|| format!("{what}: {rest:?} is not a number"))?;
    let suffix = suffix.trim();
    let limit = match (unit, suffix) {
        (Unit::Time, "ms") => value,
        (Unit::Time, "us" | "µs") => value / 1e3,
        (Unit::Time, "s") => value * 1e3,
        (Unit::Time, _) => {
            return Err(format!(
                "{what}: {rest:?} needs a time unit (us, ms or s), as in \"> 20ms\""
            ));
        }
        (Unit::Percent, "%") => {
            if value > 100.0 {
                return Err(format!("{what}: {rest:?} is above 100%"));
            }
            value
        }
        (Unit::Percent, _) => {
            return Err(format!(
                "{what}: {rest:?} needs a percent sign, as in \">= 5%\""
            ));
        }
        (Unit::Plain | Unit::Count, "") => value,
        (Unit::Plain | Unit::Count, _) => {
            return Err(format!("{what}: {rest:?} takes a plain number, no unit"));
        }
    };
    // A huge value can overflow when converted to ms.
    if !limit.is_finite() {
        return Err(format!("{what}: {rest:?} is too large"));
    }
    Ok(limit)
}

/// One `op value[unit]` for a metric of `unit`.
fn comparison(s: &str, unit: Unit, what: &str) -> Result<Comparison, String> {
    let s = s.trim();
    if s.contains("baseline") {
        return Err(format!(
            "{what}: baselines apply to threshold rules only, in a condition or clear"
        ));
    }
    let (op, rest) = split_op(s).ok_or_else(|| {
        format!("{what}: {s:?} must start with >, >=, <, <= or == followed by a value")
    })?;
    Ok(Comparison::fixed(op, value(rest, unit, what)?))
}

/// One comparison of a threshold rule: `op value[unit]`, or
/// `op baseline_<stat>_<window>` times an optional factor, plus or minus
/// an optional value, as in `> baseline_p50_7d * 1.5 + 5ms`.
fn threshold_comparison(s: &str, unit: Unit, what: &str) -> Result<Comparison, String> {
    let s = s.trim();
    if !s.contains("baseline") {
        return comparison(s, unit, what);
    }
    let (op, rest) = split_op(s).ok_or_else(|| {
        format!("{what}: {s:?} must start with >, >=, <, <= or == followed by a value")
    })?;
    let usage = || {
        format!(
            "{what}: {rest:?} must be a baseline, optionally times a factor and plus or minus \
             a value, as in \"baseline_p50_7d * 1.5 + 5ms\""
        )
    };
    // Terms with their sign; `+` and `-` only join terms.
    let mut terms: Vec<(f64, &str)> = Vec::new();
    let mut sign = 1.0;
    let mut from = 0;
    for (i, c) in rest.char_indices() {
        if c == '+' || c == '-' {
            terms.push((sign, rest[from..i].trim()));
            sign = if c == '+' { 1.0 } else { -1.0 };
            from = i + 1;
        }
    }
    terms.push((sign, rest[from..].trim()));
    let mut base: Option<BaselineTerm> = None;
    let mut limit: Option<f64> = None;
    for (sign, term) in terms {
        if term.is_empty() {
            return Err(usage());
        }
        if term.contains("baseline") {
            if base.is_some() || sign < 0.0 {
                return Err(usage());
            }
            let mut factor = 1.0;
            let mut name = None;
            for f in term.split('*').map(str::trim) {
                if f.starts_with("baseline") {
                    if name.is_some() {
                        return Err(usage());
                    }
                    name = Some(Baseline::parse(f).ok_or_else(|| {
                        format!(
                            "{what}: unknown baseline {f:?}; use baseline_<p50|p90|min|max>_<1d|7d|28d>"
                        )
                    })?);
                } else {
                    match number(f) {
                        Some(k) if k > 0.0 => factor *= k,
                        _ => return Err(usage()),
                    }
                }
            }
            let baseline = name.ok_or_else(usage)?;
            base = Some(BaselineTerm { baseline, factor });
        } else {
            if limit.is_some() || term.contains('*') {
                return Err(usage());
            }
            limit = Some(sign * value(term, unit, what)?);
        }
    }
    Ok(Comparison {
        op,
        limit: limit.unwrap_or(0.0),
        baseline: Some(base.ok_or_else(usage)?),
    })
}

/// A condition: comparisons joined by `and`, as in `"> 20ms and < 500ms"`.
pub fn parse_condition(s: &str, metric: Metric) -> Result<Vec<Comparison>, String> {
    let parts: Vec<&str> = s.split(" and ").map(str::trim).collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(format!("condition {s:?} is empty or has an empty part"));
    }
    parts
        .into_iter()
        .map(|p| threshold_comparison(p, metric.unit(), &format!("{metric} condition")))
        .collect()
}

/// `N rounds` (or a bare number) for `for` and the end of `clear`.
pub fn parse_rounds(s: &str) -> Result<u32, String> {
    let t = s.trim();
    let num = t
        .strip_suffix("rounds")
        .or_else(|| t.strip_suffix("round"))
        .unwrap_or(t)
        .trim();
    match num.parse::<u32>() {
        Ok(n) if (1..=10_000).contains(&n) => Ok(n),
        _ => Err(format!(
            "{s:?} must be a number of rounds from 1 to 10000, as in \"3 rounds\""
        )),
    }
}

/// `clear`: a condition, optionally followed by `for N rounds`.
pub fn parse_clear(s: &str, metric: Metric) -> Result<(Vec<Comparison>, Option<u32>), String> {
    match s.rfind(" for ") {
        Some(i) => {
            let rounds = parse_rounds(&s[i + 5..]).map_err(|e| format!("clear: {e}"))?;
            Ok((parse_condition(&s[..i], metric)?, Some(rounds)))
        }
        None => Ok((parse_condition(s, metric)?, None)),
    }
}

/// The largest `*N*` a pattern may use, so a rule's history stays small.
pub const MAX_ANY: u32 = 1_000;

/// One item of a SmokePing pattern.
pub fn parse_pattern_item(s: &str, kind: PatternType) -> Result<PatternItem, String> {
    let t = s.trim();
    if t == "U" {
        // Every round has a loss value; only the median can be missing.
        return match kind {
            PatternType::Rtt => Ok(PatternItem::Unknown),
            PatternType::Loss => Err(format!(
                "pattern item {s:?}: U (no reply) applies to rtt patterns only"
            )),
        };
    }
    if let Some(n) = t.strip_prefix('*').and_then(|r| r.strip_suffix('*')) {
        return match n.parse::<u32>() {
            Ok(n) if (1..=MAX_ANY).contains(&n) => Ok(PatternItem::Any(n)),
            _ => Err(format!(
                "pattern item {s:?}: a wildcard is *N* with N from 1 to {MAX_ANY}"
            )),
        };
    }
    let what = format!("pattern item {s:?}");
    match kind {
        PatternType::Loss if t.ends_with('%') => {
            comparison(t, Unit::Percent, &what).map(PatternItem::Compare)
        }
        PatternType::Loss => comparison(t, Unit::Count, &what).map(PatternItem::Count),
        // SmokePing's RTT patterns are in milliseconds without a unit;
        // "ms" is accepted too.
        PatternType::Rtt => {
            let bare = t.strip_suffix("ms").unwrap_or(t).trim_end();
            comparison(bare, Unit::Count, &what).map(PatternItem::Compare)
        }
    }
}

/// A whole pattern. It needs at least one item that is not a wildcard.
pub fn parse_pattern(items: &[String], kind: PatternType) -> Result<Pattern, String> {
    let items = items
        .iter()
        .map(|i| parse_pattern_item(i, kind))
        .collect::<Result<Vec<_>, _>>()?;
    if items.iter().all(|i| matches!(i, PatternItem::Any(_))) {
        return Err("a pattern needs at least one item that is not a wildcard".into());
    }
    Ok(Pattern { kind, items })
}

/// One round as a pattern sees it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PatternValue {
    pub loss_pct: f64,
    pub lost: u32,
    /// Median RTT in ms; `None` when nothing came back.
    pub median_ms: Option<f64>,
}

impl PatternItem {
    fn matches(&self, kind: PatternType, v: &PatternValue) -> bool {
        match (self, kind) {
            (PatternItem::Any(_), _) => true,
            (PatternItem::Unknown, PatternType::Rtt) => v.median_ms.is_none(),
            // A loss is always known.
            (PatternItem::Unknown, PatternType::Loss) => false,
            (PatternItem::Compare(c), PatternType::Loss) => c.holds(v.loss_pct),
            (PatternItem::Count(c), _) => c.holds(f64::from(v.lost)),
            (PatternItem::Compare(c), PatternType::Rtt) => v.median_ms.is_some_and(|m| c.holds(m)),
        }
    }
}

impl Pattern {
    /// Whether the pattern matches the newest rounds of `history` (oldest
    /// first): the last item is the newest round, each `*N*` takes 0 to N
    /// rounds, and older rounds before the first item do not matter.
    ///
    /// Items are taken newest first, keeping the set of history lengths
    /// still to match (`reach[k]`: `history[..k]` is left), so the work is
    /// items × history × wildcard width at most, not one try per way the
    /// wildcards could split the rounds.
    pub fn matches(&self, history: &[PatternValue]) -> bool {
        self.matches_counting(history, &mut 0)
    }

    /// [`matches`](Self::matches), adding the positions it visits to
    /// `steps`: at most `(history.len() + 1)` per item, whatever the
    /// wildcards.
    fn matches_counting(&self, history: &[PatternValue], steps: &mut u64) -> bool {
        let n = history.len();
        let mut reach = vec![false; n + 1];
        reach[n] = true;
        for item in self.items.iter().rev() {
            let mut next = vec![false; n + 1];
            match item {
                PatternItem::Any(m) => {
                    // From k, any of k, k-1, …, k-m (not below 0).
                    let m = *m as usize;
                    let mut until: Option<usize> = None;
                    for k in (0..=n).rev() {
                        *steps += 1;
                        if reach[k] {
                            until = Some(k);
                        }
                        next[k] = until.is_some_and(|u| u - k <= m);
                    }
                }
                item => {
                    for k in 1..=n {
                        *steps += 1;
                        if reach[k] && item.matches(self.kind, &history[k - 1]) {
                            next[k - 1] = true;
                        }
                    }
                }
            }
            if !next.contains(&true) {
                return false;
            }
            reach = next;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(loss_pct: f64, median_ms: Option<f64>) -> PatternValue {
        PatternValue {
            loss_pct,
            // 20 samples a round.
            lost: (loss_pct / 5.0) as u32,
            median_ms,
        }
    }

    fn pat(kind: PatternType, items: &[&str]) -> Pattern {
        let items: Vec<String> = items.iter().map(|s| s.to_string()).collect();
        parse_pattern(&items, kind).unwrap()
    }

    #[test]
    fn conditions_parse_with_units() {
        assert_eq!(
            parse_condition("> 20ms and <= 1.5s", Metric::Median).unwrap(),
            [
                Comparison::fixed(Op::Gt, 20.0),
                Comparison::fixed(Op::Le, 1500.0)
            ]
        );
        assert_eq!(
            parse_condition(">=500us", Metric::P90).unwrap()[0].limit,
            0.5
        );
        assert_eq!(
            parse_condition(">= 5%", Metric::Loss).unwrap()[0],
            Comparison::fixed(Op::Ge, 5.0)
        );
        assert_eq!(parse_condition("< 3.6", Metric::Mos).unwrap()[0].limit, 3.6);
        for (bad, metric) in [
            ("> 20", Metric::Median),
            ("20ms", Metric::Median),
            ("> 5", Metric::Loss),
            ("> 120%", Metric::Loss),
            ("< 3.6ms", Metric::Mos),
            ("> -1ms", Metric::Median),
            (&format!("> 1{}s", "0".repeat(306)), Metric::Median),
            ("> baseline_p50_7d * -2", Metric::Median),
            ("> 20ms and ", Metric::Median),
            ("", Metric::Median),
        ] {
            assert!(parse_condition(bad, metric).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn clear_takes_an_optional_round_count() {
        let (c, n) = parse_clear("< 15ms for 3 rounds", Metric::Median).unwrap();
        assert_eq!((c[0].op, c[0].limit, n), (Op::Lt, 15.0, Some(3)));
        let (_, n) = parse_clear("< 15ms", Metric::Median).unwrap();
        assert_eq!(n, None);
        assert!(parse_clear("< 15ms for ever", Metric::Median).is_err());
        assert_eq!(parse_rounds("1 round"), Ok(1));
        assert_eq!(parse_rounds("12"), Ok(12));
        assert!(parse_rounds("0 rounds").is_err());
    }

    #[test]
    fn pattern_items_follow_smokeping() {
        use PatternItem as P;
        assert_eq!(
            parse_pattern_item(">10%", PatternType::Loss),
            Ok(P::Compare(Comparison::fixed(Op::Gt, 10.0)))
        );
        assert_eq!(
            parse_pattern_item("==0", PatternType::Loss),
            Ok(P::Count(Comparison::fixed(Op::Eq, 0.0)))
        );
        assert_eq!(
            parse_pattern_item(">50", PatternType::Rtt),
            parse_pattern_item(">50ms", PatternType::Rtt)
        );
        assert_eq!(parse_pattern_item("U", PatternType::Rtt), Ok(P::Unknown));
        assert!(parse_pattern_item("U", PatternType::Loss).is_err());
        assert_eq!(
            parse_pattern_item("*12*", PatternType::Loss),
            Ok(P::Any(12))
        );
        for bad in ["*0*", "*x*", "10%", ">", ">ten"] {
            assert!(parse_pattern_item(bad, PatternType::Loss).is_err(), "{bad}");
        }
        assert!(parse_pattern(&["*3*".to_string()], PatternType::Loss).is_err());
    }

    #[test]
    fn the_last_item_is_the_newest_round() {
        // SmokePing's "bigloss": no loss, then loss above 50% in two rounds.
        let p = pat(PatternType::Loss, &["==0%", "==0%", ">50%", ">50%"]);
        let ok = v(0.0, Some(10.0));
        let bad = v(75.0, Some(10.0));
        assert!(p.matches(&[ok, ok, ok, bad, bad]));
        assert!(!p.matches(&[ok, ok, bad, bad, ok]));
        assert!(!p.matches(&[ok, bad, bad]), "too little history");
        assert!(!p.matches(&[bad, ok, bad, bad]));
    }

    #[test]
    fn wildcards_take_zero_to_n_rounds() {
        let p = pat(PatternType::Loss, &[">0%", "*3*", ">0%"]);
        let ok = v(0.0, Some(1.0));
        let lossy = v(10.0, Some(1.0));
        assert!(p.matches(&[lossy, lossy]));
        assert!(p.matches(&[lossy, ok, ok, ok, lossy]));
        assert!(!p.matches(&[lossy, ok, ok, ok, ok, lossy]));
        assert!(!p.matches(&[lossy, ok]));
        assert_eq!(p.window(), 5);
    }

    /// The plain recursive definition the matcher must agree with.
    fn reference(items: &[PatternItem], kind: PatternType, hist: &[PatternValue]) -> bool {
        let Some((last, rest)) = items.split_last() else {
            return true;
        };
        match last {
            PatternItem::Any(n) => {
                let most = (*n as usize).min(hist.len());
                (0..=most).any(|j| reference(rest, kind, &hist[..hist.len() - j]))
            }
            item => match hist.split_last() {
                Some((v, older)) => item.matches(kind, v) && reference(rest, kind, older),
                None => false,
            },
        }
    }

    proptest::proptest! {
        #[test]
        fn matching_agrees_with_the_recursive_definition(
            items in proptest::collection::vec(0u8..5, 1..7),
            losses in proptest::collection::vec(0u8..3, 0..14),
        ) {
            let items: Vec<String> = items
                .iter()
                .map(|i| match i {
                    0 => "==0%".to_string(),
                    1 => ">0%".to_string(),
                    2 => ">=50%".to_string(),
                    3 => "*1*".to_string(),
                    _ => "*3*".to_string(),
                })
                .collect();
            let Ok(p) = parse_pattern(&items, PatternType::Loss) else {
                return Ok(());
            };
            let hist: Vec<PatternValue> = losses
                .iter()
                .map(|&l| v(f64::from(l) * 50.0, Some(1.0)))
                .collect();
            proptest::prop_assert_eq!(p.matches(&hist), reference(&p.items, p.kind, &hist));
        }
    }

    #[test]
    fn many_wildcards_stay_cheap() {
        // Eight wildcard pairs over clean rounds: exponential if every
        // split of the rounds were tried.
        let mut items = vec![">0%"];
        for _ in 0..8 {
            items.extend(["*12*", "==0%"]);
        }
        let p = pat(PatternType::Loss, &items);
        let clean = vec![v(0.0, Some(1.0)); p.window()];
        let mut steps = 0;
        assert!(!p.matches_counting(&clean, &mut steps));
        // Linear: at most one visit per history position and item.
        let bound = (clean.len() as u64 + 1) * items.len() as u64;
        assert!(steps <= bound, "{steps} steps > {bound}");
    }

    #[test]
    fn rtt_patterns_use_the_median_and_u() {
        // SmokePing's "rttdetect": 3 rounds below 10 ms, then 3 above 100.
        let p = pat(
            PatternType::Rtt,
            &["<10", "<10", "<10", ">100", ">100", ">100"],
        );
        let fast = v(0.0, Some(5.0));
        let slow = v(0.0, Some(150.0));
        assert!(p.matches(&[fast, fast, fast, slow, slow, slow]));
        let dead = v(100.0, None);
        assert!(!p.matches(&[fast, fast, fast, slow, slow, dead]));
        let u = pat(PatternType::Rtt, &["U"]);
        assert!(u.matches(&[dead]));
        assert!(!u.matches(&[fast]));
    }

    #[test]
    fn rules_summarise_as_written() {
        let rule = |kind| AlertRule {
            name: "r".into(),
            kind,
            line: 1,
        };
        let t = Threshold {
            metric: Metric::Median,
            condition: parse_condition("> 20ms", Metric::Median).unwrap(),
            for_rounds: 3,
            clear: Some(parse_condition("< 15ms", Metric::Median).unwrap()),
            clear_rounds: 2,
        };
        assert_eq!(
            rule(RuleKind::Threshold(t)).summary(),
            "median > 20ms for 3 rounds; clear < 15ms for 2 rounds"
        );
        let p = pat(PatternType::Loss, &[">0%", "*3*", "==0", ">50%"]);
        assert_eq!(
            rule(RuleKind::Pattern(p)).summary(),
            "loss pattern >0% *3* ==0 >50%"
        );
        let p = pat(PatternType::Rtt, &["U", ">100"]);
        assert_eq!(rule(RuleKind::Pattern(p)).summary(), "rtt pattern U >100");
    }

    #[test]
    fn unknown_values_never_meet_a_threshold() {
        let c = parse_condition("< 10ms", Metric::Median).unwrap();
        assert!(all_hold(&c, Some(5.0)));
        assert!(!all_hold(&c, None));
        assert!(!all_hold(&c, Some(10.0)));
    }

    #[test]
    fn conditions_can_follow_a_baseline() {
        let b = |stat, days| Baseline { stat, days };
        let c = parse_condition("> baseline_p50_7d * 1.5 + 5ms", Metric::Median).unwrap();
        assert_eq!(
            c[0].baseline,
            Some(BaselineTerm {
                baseline: b(BaselineStat::P50, 7),
                factor: 1.5
            })
        );
        assert_eq!(c[0].limit, 5.0);
        assert_eq!(c[0].text(Metric::Median), "> baseline_p50_7d * 1.5 + 5ms");
        // Factor first, a subtracted value, and a fixed limit beside it.
        let c = parse_condition("< 2*baseline_max_28d - 500us and > 1ms", Metric::P90).unwrap();
        assert_eq!(c[0].baseline.unwrap().factor, 2.0);
        assert_eq!(c[0].limit, -0.5);
        assert_eq!(c[0].text(Metric::P90), "< baseline_max_28d * 2 - 0.5ms");
        assert_eq!(c[1], Comparison::fixed(Op::Gt, 1.0));
        let c = parse_condition(">= baseline_p90_1d + 2%", Metric::Loss).unwrap();
        assert_eq!(c[0].text(Metric::Loss), ">= baseline_p90_1d + 2%");

        let known = |bl: Baseline| (bl == b(BaselineStat::P50, 7)).then_some(10.0);
        let c = parse_condition("> baseline_p50_7d * 1.5 + 5ms", Metric::Median).unwrap();
        assert_eq!(eval(&c, Some(20.5), &known), Some(true));
        assert_eq!(eval(&c, Some(20.0), &known), Some(false));
        assert_eq!(eval(&c, None, &known), None);
        assert_eq!(eval(&c, Some(99.0), &|_| None), None, "unknown baseline");
        assert!(!all_hold(&c, Some(99.0)));

        for bad in [
            "> baseline_p50_2d",
            "> baseline_p95_7d",
            "> baseline",
            "> baseline_p50_7d * 0",
            "> baseline_p50_7d * x",
            "> baseline_p50_7d + 5",
            "> baseline_p50_7d + 5ms + 1ms",
            "> 5ms - baseline_p50_7d",
            "> baseline_p50_7d + baseline_p90_7d",
            "> baseline_p50_7d * baseline_p90_7d",
            "> baseline_p50_7d +",
            "baseline_p50_7d",
        ] {
            assert!(parse_condition(bad, Metric::Median).is_err(), "{bad:?}");
        }
        assert!(parse_pattern_item(">baseline_p50_7d", PatternType::Rtt).is_err());
        let t = Threshold {
            metric: Metric::Median,
            condition: parse_condition("> baseline_p50_7d * 2", Metric::Median).unwrap(),
            for_rounds: 1,
            clear: Some(
                parse_condition("< baseline_p50_7d and < baseline_p90_1d", Metric::Median).unwrap(),
            ),
            clear_rounds: 1,
        };
        assert_eq!(
            t.baselines(),
            [b(BaselineStat::P50, 7), b(BaselineStat::P90, 1)]
        );
    }
}
