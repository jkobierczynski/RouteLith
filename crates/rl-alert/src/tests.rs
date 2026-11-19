use proptest::prelude::*;
use rl_core::alert::{self, AlertRule, Metric, PatternType, RuleKind, Threshold};

use super::*;

const STEP: i64 = 60_000;

fn threshold(
    name: &str,
    metric: Metric,
    cond: &str,
    for_rounds: u32,
    clear: Option<&str>,
) -> AlertRule {
    let (clear, clear_rounds) = match clear {
        Some(c) => {
            let (c, n) = alert::parse_clear(c, metric).unwrap();
            (Some(c), n.unwrap_or(for_rounds))
        }
        None => (None, for_rounds),
    };
    AlertRule {
        name: name.into(),
        kind: RuleKind::Threshold(Threshold {
            metric,
            condition: alert::parse_condition(cond, metric).unwrap(),
            for_rounds,
            clear,
            clear_rounds,
        }),
        line: 1,
    }
}

fn pattern(name: &str, kind: PatternType, items: &[&str]) -> AlertRule {
    let items: Vec<String> = items.iter().map(|s| s.to_string()).collect();
    AlertRule {
        name: name.into(),
        kind: RuleKind::Pattern(alert::parse_pattern(&items, kind).unwrap()),
        line: 1,
    }
}

/// A round of 20 samples at `i` steps, all answered in `ms`, `lost` lost.
fn round(i: i64, ms: u32, lost: u32) -> RoundValues {
    let rtts = vec![ms * 1000; (20 - lost) as usize];
    RoundValues::from_sorted(i * STEP, 20, &rtts)
}

fn engine(rule: AlertRule) -> Engine {
    let name = rule.name.clone();
    Engine::new(vec![rule], [(7, vec![name])])
}

/// Feed rounds; return (index, raised) of each transition.
fn run(e: &mut Engine, rounds: &[RoundValues]) -> Vec<(usize, bool)> {
    let mut out = Vec::new();
    for (i, r) in rounds.iter().enumerate() {
        for t in e.observe(7, r) {
            out.push((i, t.raised));
        }
    }
    out
}

#[test]
fn round_values_follow_smokeping() {
    let r = RoundValues::from_sorted(0, 5, &[1000, 2000, 3000, 4000]);
    assert_eq!(r.median_us, Some(2500));
    assert_eq!(r.p90_us, Some(4000));
    assert_eq!(r.metric(Metric::Loss), Some(20.0));
    assert_eq!(r.metric(Metric::Median), Some(2.5));
    // 20 % loss sinks the MOS; a clean round scores well.
    assert!(r.metric(Metric::Mos).unwrap() < 3.0);
    assert!(round(0, 5, 0).metric(Metric::Mos).unwrap() > 4.0);
    let dead = RoundValues::from_sorted(0, 5, &[]);
    assert_eq!(dead.metric(Metric::Median), None);
    assert_eq!(dead.metric(Metric::Mos), None);
    assert_eq!(dead.metric(Metric::Loss), Some(100.0));
    assert_eq!(
        RoundValues::from_sorted(0, 0, &[]).metric(Metric::Loss),
        None
    );
}

#[test]
fn a_threshold_needs_its_streak_and_clears_with_hysteresis() {
    let mut e = engine(threshold(
        "slow",
        Metric::Median,
        "> 20ms",
        3,
        Some("< 15ms for 2 rounds"),
    ));
    let ms = [10, 30, 30, 10, 30, 30, 30, 18, 12, 18, 12, 12, 30];
    let rounds: Vec<_> = ms
        .iter()
        .enumerate()
        .map(|(i, &m)| round(i as i64, m, 0))
        .collect();
    // Raised at the third 30 in a row (index 6), not 18 ms (still > 15),
    // cleared after two rounds below 15 in a row (index 11).
    assert_eq!(run(&mut e, &rounds), [(6, true), (11, false)]);
}

#[test]
fn raise_and_clear_carry_the_start_of_the_degradation() {
    let mut e = engine(threshold("slow", Metric::Median, "> 20ms", 2, None));
    let mut all = Vec::new();
    for (i, ms) in [10, 30, 40, 10, 10].into_iter().enumerate() {
        all.extend(e.observe(7, &round(i as i64, ms, 0)));
    }
    assert_eq!(all.len(), 2);
    assert_eq!((all[0].ts_ms, all[0].since_ms), (2 * STEP, STEP));
    assert_eq!(all[0].value, Some(40.0));
    assert_eq!(
        all[0].message,
        "slow raised: median 40ms > 20ms for 2 rounds"
    );
    assert_eq!((all[1].ts_ms, all[1].since_ms), (4 * STEP, STEP));
    assert_eq!(all[1].message, "slow cleared: median 10ms");
    assert!(e.active().is_empty());
}

#[test]
fn a_round_without_a_value_breaks_both_streaks() {
    let mut e = engine(threshold("slow", Metric::Median, "> 20ms", 2, None));
    let rounds = [
        round(0, 30, 0),
        round(1, 0, 20), // all lost: no median
        round(2, 30, 0),
        round(3, 30, 0), // raised
        round(4, 10, 0),
        round(5, 0, 20),
        round(6, 10, 0),
        round(7, 10, 0), // cleared
    ];
    assert_eq!(run(&mut e, &rounds), [(3, true), (7, false)]);
}

#[test]
fn loss_and_mos_thresholds() {
    let mut e = engine(threshold("lossy", Metric::Loss, ">= 10%", 1, None));
    let rounds = [round(0, 5, 1), round(1, 5, 2), round(2, 5, 0)];
    assert_eq!(run(&mut e, &rounds), [(1, true), (2, false)]);

    let mut e = engine(threshold("voice", Metric::Mos, "< 3.6", 1, None));
    let rounds = [round(0, 5, 0), round(1, 5, 12), round(2, 5, 0)];
    assert_eq!(run(&mut e, &rounds), [(1, true), (2, false)]);
}

#[test]
fn patterns_raise_while_they_match() {
    let mut e = engine(pattern("burst", PatternType::Loss, &[">0%", "*3*", ">0%"]));
    let lost = [0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1];
    let rounds: Vec<_> = lost
        .iter()
        .enumerate()
        .map(|(i, &l)| round(i as i64, 5, l))
        .collect();
    // 1 _ _ 1 matches at index 4; one clean round later (index 5) the
    // newest round no longer has loss, so the pattern stops matching.
    assert_eq!(run(&mut e, &rounds), [(4, true), (5, false), (11, true)]);
}

#[test]
fn warm_history_counts_but_does_not_raise() {
    let mut e = engine(pattern("burst", PatternType::Loss, &[">0%", ">0%"]));
    e.warm(7, &round(0, 5, 1));
    assert!(e.active().is_empty());
    let t = e.observe(7, &round(1, 5, 1));
    assert_eq!(t.len(), 1);
    assert!(t[0].raised);
    assert_eq!(t[0].message, "burst raised: loss pattern matched (loss 5%)");
}

#[test]
fn restored_alerts_clear_normally_and_are_not_raised_twice() {
    let mut e = engine(threshold("slow", Metric::Median, "> 20ms", 1, None));
    assert!(e.restore(7, "slow", 5, Some(31.0)));
    assert!(!e.restore(7, "other", 5, None));
    assert!(!e.restore(8, "slow", 5, None));
    assert_eq!(
        e.active(),
        [ActiveAlert {
            series: 7,
            rule: "slow".into(),
            since_ms: 5,
            value: Some(31.0)
        }]
    );
    // Still slow: no second raise.
    assert!(e.observe(7, &round(1, 40, 0)).is_empty());
    let t = e.observe(7, &round(2, 10, 0));
    assert_eq!((t[0].raised, t[0].since_ms), (false, 5));
}

#[test]
fn rules_apply_only_to_their_series() {
    let rules = vec![
        threshold("a", Metric::Median, "> 1ms", 1, None),
        threshold("b", Metric::Loss, "> 0%", 1, None),
    ];
    let mut e = Engine::new(
        rules,
        [
            (1, vec!["a".into()]),
            (2, vec!["a".into(), "b".into(), "gone".into()]),
        ],
    );
    assert!(e.applies(1, "a") && !e.applies(1, "b") && e.applies(2, "b"));
    assert!(e.observe(3, &round(0, 5, 1)).is_empty());
    let t = e.observe(2, &round(0, 5, 1));
    assert_eq!(
        t.iter().map(|t| t.rule.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert_eq!(e.observe(1, &round(0, 5, 1)).len(), 1);
    assert_eq!(e.active().len(), 3);
}

#[test]
fn the_event_log_says_what_is_still_raised() {
    let ev = |t: i64, kind, series: u64, rule: &str| {
        let mut e = Event::new(t, kind, "local", "");
        e.series = Some(series);
        e.rule = Some(rule.into());
        e.since = Some(t - 1);
        e
    };
    let events = [
        ev(10, EventKind::AlertRaised, 1, "a"),
        ev(11, EventKind::AlertRaised, 2, "a"),
        ev(12, EventKind::AlertCleared, 1, "a"),
        Event::new(13, EventKind::ServerStopped, "local", ""),
        ev(14, EventKind::AlertRaised, 1, "b"),
    ];
    let active = active_from_events(&events);
    let got: Vec<_> = active
        .iter()
        .map(|a| (a.series, a.rule.as_str(), a.since_ms))
        .collect();
    assert_eq!(got, [(1, "b", 13), (2, "a", 10)]);
}

proptest! {
    /// Raises and clears alternate; a raise comes only after `for` rounds
    /// in a row met the condition, a clear only after `clear` rounds in a
    /// row had a value that did not.
    #[test]
    fn threshold_hysteresis_holds(
        values in proptest::collection::vec(proptest::option::of(0u32..40), 1..200),
        for_rounds in 1u32..5,
    ) {
        let mut e = engine(threshold("t", Metric::Median, "> 20ms", for_rounds, None));
        let met = |v: Option<u32>| v.is_some_and(|ms| ms > 20);
        let n = for_rounds as usize;
        let mut active = false;
        for (i, v) in values.iter().enumerate() {
            let r = match v {
                Some(ms) => round(i as i64, *ms, 0),
                None => round(i as i64, 0, 20),
            };
            for t in e.observe(7, &r) {
                prop_assert_ne!(t.raised, active, "transitions alternate");
                prop_assert!(i + 1 >= n);
                let window = &values[i + 1 - n..=i];
                if t.raised {
                    prop_assert!(window.iter().all(|&v| met(v)));
                } else {
                    prop_assert!(window.iter().all(|&v| v.is_some() && !met(v)));
                }
                active = t.raised;
            }
        }
        prop_assert_eq!(active, !e.active().is_empty());
    }
}
