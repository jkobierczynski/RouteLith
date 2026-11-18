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
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let rank = ((p / 100.0 * self.count as f64).ceil() as u64).clamp(1, self.count);
        let mut seen = 0;
        for (i, &c) in self.counts.iter().enumerate() {
            seen += c;
            if seen >= rank {
                return Some(upper(i).min(self.max));
            }
        }
        Some(self.max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
