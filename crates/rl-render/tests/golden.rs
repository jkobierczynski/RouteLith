//! Golden tests: the three `ctl render` ranges over ten days of synthetic
//! rounds. Regenerate with `UPDATE_GOLDEN=1 cargo test -p rl-render`.

use std::path::PathBuf;

use rl_render::{Graph, Round};

/// 2025-11-18 00:00 UTC.
const END_MS: i64 = 1_763_424_000_000;
const STEP_MS: i64 = 300_000;
const HOUR_MS: i64 = 3_600_000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    /// Uniform in `0.0..1.0`.
    fn unit(&mut self) -> f64 {
        (self.next() % 1_000_000) as f64 / 1e6
    }
}

/// Ten days of 20-sample rounds every 5 minutes, ending at `END_MS`:
/// a daily latency swell, a congested afternoon with loss, a 40-minute
/// outage, a 3-hour gap with no data, and occasional spikes.
fn rounds() -> Vec<(i64, u16, Vec<u32>)> {
    let mut rng = Rng(7);
    let mut out = Vec::new();
    let start = END_MS - 10 * 24 * HOUR_MS;
    let mut ts = start + 17_000;
    while ts <= END_MS {
        let hours_before_end = (END_MS - ts) as f64 / HOUR_MS as f64;
        let hour_of_day = (ts % (24 * HOUR_MS)) as f64 / HOUR_MS as f64;
        let gap = (50.0..53.0).contains(&hours_before_end);
        if !gap {
            let outage = (5.0..5.67).contains(&hours_before_end);
            let congested =
                (1.0..2.5).contains(&hours_before_end) || (26.0..28.0).contains(&hours_before_end);
            // A daily triangle wave (no libm, so every platform agrees).
            let phase = hour_of_day / 12.0;
            let base = 5.0 + 6.0 * if phase < 1.0 { phase } else { 2.0 - phase };
            let (jitter, loss) = if congested {
                (25.0, 0.12)
            } else {
                (1.5, 0.004)
            };
            let mut rtts: Vec<u32> = Vec::new();
            for _ in 0..20 {
                if outage || rng.unit() < loss {
                    continue;
                }
                let mut ms = base + jitter * rng.unit() * rng.unit();
                if rng.unit() < 0.01 {
                    ms += 40.0;
                }
                rtts.push((ms * 1000.0) as u32);
            }
            rtts.sort_unstable();
            out.push((ts, 20, rtts));
        }
        ts += STEP_MS;
    }
    out
}

fn check(name: &str, range_ms: i64) {
    let data = rounds();
    let rounds: Vec<Round<'_>> = data
        .iter()
        .map(|(ts, sent, rtts)| Round {
            ts_ms: *ts,
            sent: *sent,
            rtts_us: rtts,
        })
        .collect();
    let svg = rl_render::render(
        &rounds,
        &Graph {
            title: "gateway (v4)",
            from_ms: END_MS - range_ms,
            to_ms: END_MS,
            step_ms: Some(STEP_MS),
            width: Graph::DEFAULT_WIDTH,
            height: Graph::DEFAULT_HEIGHT,
            totals: None,
        },
    );
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.svg"));
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &svg).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run with UPDATE_GOLDEN=1)", path.display()));
    assert!(
        svg == want,
        "{name}.svg differs from the golden file; inspect and rerun with UPDATE_GOLDEN=1"
    );
}

#[test]
fn range_3h() {
    check("3h", 3 * HOUR_MS);
}

#[test]
fn range_30h() {
    check("30h", 30 * HOUR_MS);
}

#[test]
fn range_10d() {
    check("10d", 240 * HOUR_MS);
}
