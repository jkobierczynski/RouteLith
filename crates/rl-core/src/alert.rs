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
                        .map(|c| format!("{} {}", c.op.as_str(), t.metric.format(c.limit)))
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
                            format!("{}{}%", c.op.as_str(), trim(c.limit))
                        }
                        PatternItem::Compare(c) | PatternItem::Count(c) => {
                            format!("{}{}", c.op.as_str(), trim(c.limit))
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

/// `value op limit`, the limit in the metric's unit (ms, percent, plain).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Comparison {
    pub op: Op,
    pub limit: f64,
}

impl Comparison {
    pub fn holds(&self, value: f64) -> bool {
        self.op.holds(value, self.limit)
    }
}

/// Every comparison holds for `value`; an unknown value never matches.
pub fn all_hold(cmps: &[Comparison], value: Option<f64>) -> bool {
    value.is_some_and(|v| cmps.iter().all(|c| c.holds(v)))
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

/// One `op value[unit]` for a metric of `unit`.
fn comparison(s: &str, unit: Unit, what: &str) -> Result<Comparison, String> {
    let s = s.trim();
    if s.contains("baseline") {
        return Err(format!(
            "{what}: baselines are not available yet (they arrive later in milestone M2)"
        ));
    }
    let (op, rest) = split_op(s).ok_or_else(|| {
        format!("{what}: {s:?} must start with >, >=, <, <= or == followed by a value")
    })?;
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
    Ok(Comparison { op, limit })
}

/// A condition: comparisons joined by `and`, as in `"> 20ms and < 500ms"`.
pub fn parse_condition(s: &str, metric: Metric) -> Result<Vec<Comparison>, String> {
    let parts: Vec<&str> = s.split(" and ").map(str::trim).collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(format!("condition {s:?} is empty or has an empty part"));
    }
    parts
        .into_iter()
        .map(|p| comparison(p, metric.unit(), &format!("{metric} condition")))
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
        return Ok(PatternItem::Unknown);
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
    pub fn matches(&self, history: &[PatternValue]) -> bool {
        fn go(items: &[PatternItem], kind: PatternType, hist: &[PatternValue]) -> bool {
            let Some((last, rest)) = items.split_last() else {
                return true;
            };
            match last {
                PatternItem::Any(n) => {
                    let most = (*n as usize).min(hist.len());
                    (0..=most).any(|j| go(rest, kind, &hist[..hist.len() - j]))
                }
                item => match hist.split_last() {
                    Some((v, older)) => item.matches(kind, v) && go(rest, kind, older),
                    None => false,
                },
            }
        }
        go(&self.items, self.kind, history)
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
                Comparison {
                    op: Op::Gt,
                    limit: 20.0
                },
                Comparison {
                    op: Op::Le,
                    limit: 1500.0
                }
            ]
        );
        assert_eq!(
            parse_condition(">=500us", Metric::P90).unwrap()[0].limit,
            0.5
        );
        assert_eq!(
            parse_condition(">= 5%", Metric::Loss).unwrap()[0],
            Comparison {
                op: Op::Ge,
                limit: 5.0
            }
        );
        assert_eq!(parse_condition("< 3.6", Metric::Mos).unwrap()[0].limit, 3.6);
        for (bad, metric) in [
            ("> 20", Metric::Median),
            ("20ms", Metric::Median),
            ("> 5", Metric::Loss),
            ("> 120%", Metric::Loss),
            ("< 3.6ms", Metric::Mos),
            ("> -1ms", Metric::Median),
            ("> baseline_p50_7d * 2", Metric::Median),
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
            Ok(P::Compare(Comparison {
                op: Op::Gt,
                limit: 10.0
            }))
        );
        assert_eq!(
            parse_pattern_item("==0", PatternType::Loss),
            Ok(P::Count(Comparison {
                op: Op::Eq,
                limit: 0.0
            }))
        );
        assert_eq!(
            parse_pattern_item(">50", PatternType::Rtt),
            parse_pattern_item(">50ms", PatternType::Rtt)
        );
        assert_eq!(parse_pattern_item("U", PatternType::Rtt), Ok(P::Unknown));
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
        // U never matches a loss value.
        assert!(!pat(PatternType::Loss, &["U"]).matches(&[dead]));
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
}
