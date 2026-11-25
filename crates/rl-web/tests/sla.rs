//! SLA reports against a month of synthetic rounds (doc §21.6: "the SLA
//! report for a month of synthetic data matches availability and
//! percentiles computed by hand").

use rl_core::config::Sla;
use rl_store::{ErrorCounts, Reader, SeriesKey, StoredRound, Writer, WriterOptions};
use rl_web::sla::{self, Month, ReportSeries, Verdict};

/// 2027-02-01T00:00:00Z: a 28-day month.
const FEB: i64 = 1_801_440_000_000;
const MAR: i64 = 1_803_859_200_000;
const STEP: i64 = 300_000;
const DAY: i64 = 86_400_000;

/// Replies of round `i` (4 sent): none for 3 hours on day 3, three
/// every tenth round, else four; 50 ms on days 10 to 12, else 10 ms.
fn replies(i: i64) -> Vec<u32> {
    let t = i * STEP;
    let day = t / DAY;
    if day == 3 && (t % DAY) >= 6 * 3_600_000 && (t % DAY) < 9 * 3_600_000 {
        return Vec::new();
    }
    let rtt = if (10..=12).contains(&day) {
        50_000
    } else {
        10_000
    };
    vec![rtt; if i % 10 == 0 { 3 } else { 4 }]
}

fn sla(name: &str, availability: f64, loss: f64, latency_ms: u32) -> Sla {
    Sla {
        name: name.into(),
        targets: Vec::new(),
        groups: vec!["isp".into()],
        availability: Some(availability),
        loss: Some(loss),
        latency_us: Some(latency_ms * 1000),
        percentile: 95,
        line: 1,
    }
}

#[test]
fn a_month_of_rounds_matches_the_hand_count() {
    let dir = tempfile::tempdir().unwrap();
    // One day of raw rounds, so the month is read from the hourly tier.
    let opts = WriterOptions {
        raw_days: 1,
        ..WriterOptions::default()
    };
    let (mut w, _) = Writer::open(dir.path(), opts, FEB).unwrap();
    let key = SeriesKey::new("home", "uplink", "v4");
    let id = w.register(std::slice::from_ref(&key)).unwrap()[0];
    w.set_steps(&[(id, STEP as u64)]).unwrap();
    let n = (MAR - FEB) / STEP;
    for i in 0..n {
        w.append(
            id,
            StoredRound {
                ts_ms: FEB + i * STEP,
                sent: 4,
                rtts_us: replies(i),
                errors: ErrorCounts::default(),
                resolved: None,
                timing: None,
                flags: 0,
            },
        )
        .unwrap();
    }
    w.maintain(MAR + 3 * DAY).unwrap();
    w.close().unwrap();
    let reader = Reader::open(dir.path()).unwrap();

    let series = [ReportSeries {
        id,
        key,
        group: "isp".into(),
        step_ms: STEP as u64,
    }];
    let month = Month::parse("2027-02").unwrap();
    assert_eq!((month.start_ms(), month.end_ms()), (FEB, MAR));
    let slas = [sla("strict", 99.9, 1.0, 20), sla("loose", 99.0, 5.0, 60)];
    let r = sla::build(&reader, &slas, &series, "home", month, MAR + 3 * DAY).unwrap();
    assert!(!r.partial());

    // By hand: 8064 rounds; 36 without a reply (3 h); 4 lost in each of
    // those and 1 in every tenth round outside them.
    assert_eq!(n, 8064);
    let tenth_in_outage = (0..n)
        .filter(|i| i % 10 == 0 && replies(*i).is_empty())
        .count() as u64;
    let lost = 36 * 4 + (807 - tenth_in_outage);
    let row = &r.sections[0].rows[0];
    assert_eq!(
        (row.expected, row.rounds, row.down, row.estimated_hours),
        (8064, 8064, 36, 0)
    );
    assert_eq!(row.sent, 4 * 8064);
    assert_eq!(row.sent - row.received, lost);
    assert_eq!(row.downtime_ms(), 3 * 3_600_000);
    let availability = 100.0 * (8064.0 - 36.0) / 8064.0;
    assert!((row.availability().unwrap() - availability).abs() < 1e-9);
    assert!((row.loss().unwrap() - 100.0 * lost as f64 / 32256.0).abs() < 1e-9);
    // 3 of 28 days are slow: more than 5 % of replies, less than half.
    assert_eq!(row.latency_us, Some(50_000), "p95");
    assert_eq!(row.median_us, Some(10_000));

    let strict = &r.sections[0];
    assert_eq!(strict.availability(row), Some(Verdict::Missed));
    assert_eq!(strict.loss(row), Some(Verdict::Missed));
    assert_eq!(strict.latency(row), Some(Verdict::Missed));
    let loose = &r.sections[1];
    assert_eq!(loose.overall(&loose.rows[0]), Verdict::Met);

    let html = sla::html(&r);
    assert!(html.contains("SLA report, February 2027"), "{html}");
    assert!(html.contains("99.554 %"), "availability shown");
    assert!(html.contains("3 h"), "downtime shown");
    assert!(html.contains("badge missed") && html.contains("badge met"));
    let csv = sla::csv(&r);
    let lines: Vec<&str> = csv.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("month,sla,target,"));
    assert!(
        lines[1].starts_with("2027-02,strict,uplink,v4,isp,"),
        "{}",
        lines[1]
    );
    assert!(
        lines[1].contains(",8064,8064,100.00,36,180,99.5536,99.9000,"),
        "{}",
        lines[1]
    );
    assert!(
        lines[1].ends_with(",95,50.000,20.000,10.000,0,missed"),
        "{}",
        lines[1]
    );
    assert!(lines[2].ends_with(",met"));

    // While a month lasts, it is reported so far.
    let r = sla::build(&reader, &slas, &series, "home", month, FEB + 7 * DAY).unwrap();
    assert!(r.partial());
    assert_eq!(r.sections[0].rows[0].expected, 7 * 288);
    assert!(
        sla::build(
            &reader,
            &slas,
            &series,
            "home",
            Month::parse("2027-04").unwrap(),
            MAR
        )
        .is_err()
    );
}

#[test]
fn months_parse_and_step() {
    assert_eq!(
        Month::parse("2026-11").map(|m| m.start_ms()),
        Some(1_793_491_200_000)
    );
    assert_eq!(Month::parse("2026-12").unwrap().end_ms(), 1_798_761_600_000);
    for bad in ["2026-13", "2026-1", "26-11", "2026/11", ""] {
        assert_eq!(Month::parse(bad), None, "{bad}");
    }
    let jan = Month::parse("2027-01").unwrap();
    assert_eq!(jan.previous().to_string(), "2026-12");
    assert_eq!(Month::of(FEB + 5), Month::parse("2027-02").unwrap());
    assert_eq!(Month::of(FEB - 1).title(), "January 2027");
}

#[test]
fn percentiles_weigh_hours_by_their_replies() {
    use rl_store::{QUANTILES, RollupPoint};
    let p = |received: u32, v: u32| RollupPoint {
        ts_ms: 0,
        rounds: 12,
        sent: received,
        received,
        quantiles_us: vec![v; QUANTILES],
        down: Some(0),
    };
    // 900 replies at 1 ms, 100 at 9 ms.
    let points = [p(900, 1000), p(100, 9000)];
    assert_eq!(sla::percentile(&points, 0.5), Some(1000));
    assert_eq!(sla::percentile(&points, 0.9), Some(1000));
    assert_eq!(sla::percentile(&points, 0.91), Some(9000));
    assert_eq!(sla::percentile(&[], 0.5), None);
}
