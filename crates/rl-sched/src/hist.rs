//! A small fixed-bucket histogram for scheduling lateness.

/// Microsecond values in buckets of 10 µs up to 1 ms, 1 ms up to 100 ms and
/// 100 ms up to 60 s (anything later lands in the last bucket).
/// Percentiles report the bucket's upper bound, so they never understate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Histogram {
    counts: Vec<u64>,
    count: u64,
    max: u64,
}

const FINE: u64 = 100; // 0..1 ms, 10 µs each
const MID: u64 = 99; // 1..100 ms, 1 ms each
const COARSE: u64 = 600; // 100 ms..60 s, 100 ms each

impl Default for Histogram {
    fn default() -> Self {
        Self {
            counts: vec![0; (FINE + MID + COARSE) as usize],
            count: 0,
            max: 0,
        }
    }
}

fn bucket(us: u64) -> usize {
    let b = if us < 1_000 {
        us / 10
    } else if us < 100_000 {
        FINE + (us - 1_000) / 1_000
    } else {
        (FINE + MID + (us - 100_000) / 100_000).min(FINE + MID + COARSE - 1)
    };
    b as usize
}

fn upper(bucket: usize) -> u64 {
    let b = bucket as u64;
    if b < FINE {
        (b + 1) * 10
    } else if b < FINE + MID {
        1_000 + (b - FINE + 1) * 1_000
    } else {
        100_000 + (b - FINE - MID + 1) * 100_000
    }
}

impl Histogram {
    pub fn record(&mut self, us: u64) {
        self.counts[bucket(us)] += 1;
        self.count += 1;
        self.max = self.max.max(us);
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn max(&self) -> u64 {
        self.max
    }

    /// Upper bound of the bucket holding the `p`-th percentile (nearest
    /// rank), capped at the maximum seen. `None` when empty.
    pub fn percentile(&self, p: f64) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        // Nearest rank, computed exactly in thousandths of a percent so
        // that, say, p7 of 100 values is rank 7 and not 8.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let milli = (p.clamp(0.0, 100.0) * 1000.0).round() as u128;
        let rank = (milli * u128::from(self.count)).div_ceil(100_000);
        let rank = u64::try_from(rank).unwrap_or(u64::MAX).clamp(1, self.count);
        let last = self.counts.len() - 1;
        let mut seen = 0;
        for (i, &c) in self.counts.iter().enumerate() {
            seen += c;
            if seen >= rank {
                // The last bucket has no upper bound: report what was seen.
                return Some(if i == last {
                    self.max
                } else {
                    upper(i).min(self.max)
                });
            }
        }
        Some(self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflow_bucket_reports_the_maximum() {
        let mut h = Histogram::default();
        h.record(120_000_000);
        assert_eq!(h.percentile(99.0), Some(120_000_000));
    }

    #[test]
    fn integral_percentiles_use_the_exact_rank() {
        let mut h = Histogram::default();
        for _ in 0..7 {
            h.record(1_000);
        }
        for _ in 0..93 {
            h.record(10_000);
        }
        assert_eq!(h.percentile(7.0), Some(2_000));
        assert_eq!(h.percentile(8.0), Some(10_000));
    }

    #[test]
    fn buckets_are_contiguous() {
        for us in [
            0,
            9,
            10,
            999,
            1_000,
            1_999,
            99_999,
            100_000,
            59_999_999,
            10u64.pow(9),
        ] {
            let b = bucket(us);
            assert!(us < upper(b) || b == bucket(u64::MAX), "{us}");
            if b > 0 {
                assert!(us >= upper(b - 1), "{us}");
            }
        }
    }

    #[test]
    fn percentiles_round_up_to_bucket_bounds() {
        let mut h = Histogram::default();
        for us in 1..=100 {
            h.record(us * 100); // 0.1 .. 10 ms
        }
        // Rank 50 is 5,000 µs, in the bucket [5 ms, 6 ms).
        assert_eq!(h.percentile(50.0), Some(6_000));
        assert_eq!(h.percentile(99.0), Some(10_000));
        assert_eq!(h.max(), 10_000);
        assert_eq!(Histogram::default().percentile(99.0), None);
    }
}
