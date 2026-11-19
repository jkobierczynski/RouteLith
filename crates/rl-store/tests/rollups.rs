//! Rollup tiers, retention and recorded steps, end to end.

use rl_store::{
    ErrorCounts, QUANTILES, Reader, Resolution, SeriesKey, StoredRound, Tier, Writer,
    WriterOptions, layout, quantiles,
};

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;
const STEP_MS: i64 = 300_000;
/// 2026-11-18 00:00 UTC.
const T0: i64 = 20_775 * DAY_MS;

/// A round whose samples are `base + 0..20`, with one lost every 7th round.
fn round(i: i64) -> StoredRound {
    let base = 10_000 + u32::try_from(i % 50).unwrap() * 100;
    let mut rtts: Vec<u32> = (0..20).map(|k| base + k).collect();
    if i % 7 == 0 {
        rtts.pop();
    }
    StoredRound {
        ts_ms: T0 + i * STEP_MS,
        sent: 20,
        rtts_us: rtts,
        errors: ErrorCounts::default(),
        resolved: Some("192.0.2.10".parse().unwrap()),
        timing: None,
        flags: 0,
    }
}

#[test]
fn sealed_days_roll_up_exactly_and_expire_by_tier() {
    let dir = tempfile::tempdir().unwrap();
    let opts = WriterOptions {
        raw_days: 2,
        r1h_days: 3,
        r1d_days: 4,
        ..WriterOptions::default()
    };
    let (mut w, _) = Writer::open(dir.path(), opts, T0).unwrap();
    let [id] = w.register(&[SeriesKey::new("local", "gw", "v4")]).unwrap()[..] else {
        panic!()
    };
    w.set_steps(&[(id, 300_000)]).unwrap();
    // Two whole days of rounds.
    let rounds: Vec<StoredRound> = (0..2 * 288).map(round).collect();
    for r in &rounds {
        w.append(id, r.clone()).unwrap();
    }
    w.sync().unwrap();

    // Before any seal, a tier read consolidates the raw rounds itself.
    let reader = Reader::open(dir.path()).unwrap();
    assert_eq!(reader.step_ms(id), Some(300_000));
    let live = reader
        .read_tier(id, Tier::R1h, T0, T0 + 2 * DAY_MS)
        .unwrap();
    assert_eq!(live.len(), 48);

    // Seal both days: their rollups are written.
    w.maintain(T0 + 2 * DAY_MS + HOUR_MS).unwrap();
    assert_eq!(w.stats().rolled_days, 2);
    let reader = Reader::open(dir.path()).unwrap();
    let hours = reader
        .read_tier(id, Tier::R1h, T0, T0 + 2 * DAY_MS)
        .unwrap();
    assert_eq!(hours, live, "stored points equal the on-the-fly ones");
    let first: Vec<u32> = {
        let mut all: Vec<u32> = rounds[..12]
            .iter()
            .flat_map(|r| r.rtts_us.clone())
            .collect();
        all.sort_unstable();
        all
    };
    assert_eq!(hours[0].quantiles_us, quantiles(&first));
    assert_eq!(hours[0].quantiles_us.len(), QUANTILES);
    assert_eq!((hours[0].rounds, hours[0].sent), (12, 240));
    assert_eq!(hours[0].received, 240 - 2); // rounds 0 and 7 lost one each
    let days = reader
        .read_tier(id, Tier::R1d, T0, T0 + 2 * DAY_MS)
        .unwrap();
    assert_eq!(days.len(), 2);
    assert_eq!(days[0].rounds, 288);

    // Maintenance again on the same day changes nothing.
    w.maintain(T0 + 2 * DAY_MS + 2 * HOUR_MS).unwrap();
    assert_eq!(w.stats().rolled_days, 2);

    // A restart rebuilds nothing either.
    w.close().unwrap();
    let (mut w, _) = Writer::open(dir.path(), opts, T0 + 2 * DAY_MS + 3 * HOUR_MS).unwrap();
    assert_eq!(w.stats().rolled_days, 0);

    // Day 4: raw kept 2 days, so day 0 and 1's segments go (before day 2).
    w.maintain(T0 + 4 * DAY_MS + HOUR_MS).unwrap();
    assert!(layout::segment_file_names(dir.path(), id).is_empty());
    let reader = Reader::open(dir.path()).unwrap();
    assert!(reader.read(id, 0, i64::MAX).unwrap().is_empty());
    // The rollups outlive the raw data.
    assert_eq!(
        reader.read_tier(id, Tier::R1h, 0, i64::MAX).unwrap().len(),
        48
    );
    // A 2-day range now comes from rollups, not the (deleted) raw tier.
    let (res, pts) = reader.read_points(id, T0, T0 + 2 * DAY_MS, 800).unwrap();
    assert_eq!(res, Resolution::Rollup(Tier::R1h));
    assert_eq!(pts.len(), 48);
    w.close().unwrap();
}

#[test]
fn ranges_pick_their_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let (mut w, _) = Writer::open(dir.path(), WriterOptions::default(), T0).unwrap();
    let [id] = w.register(&[SeriesKey::new("local", "gw", "v4")]).unwrap()[..] else {
        panic!()
    };
    w.set_steps(&[(id, 300_000)]).unwrap();
    for i in 0..288 {
        w.append(id, round(i)).unwrap();
    }
    w.sync().unwrap();
    let r = Reader::open(dir.path()).unwrap();
    // 3 h at 800 points: raw (36 rounds).
    let (res, pts) = r.read_points(id, T0, T0 + 3 * HOUR_MS - 1, 800).unwrap();
    assert_eq!((res, pts.len()), (Resolution::Raw, 36));
    // 10 days at 100 points: 2880 rounds is too many, 240 hours too.
    let (res, _) = r.read_points(id, T0, T0 + 10 * DAY_MS, 100).unwrap();
    assert_eq!(res, Resolution::Rollup(Tier::R1d));
    // 30 h at 50 points: hourly.
    let (res, pts) = r.read_points(id, T0, T0 + 30 * HOUR_MS, 50).unwrap();
    assert_eq!(res, Resolution::Rollup(Tier::R1h));
    assert_eq!(pts.len(), 24);
    drop(w);
}
