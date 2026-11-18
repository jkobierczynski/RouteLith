//! Summary statistics of one round.

use crate::round::Sample;

/// Summary of a round. RTT fields are `None` when every sample was lost.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RoundStats {
    pub sent: u32,
    pub received: u32,
    pub min_us: Option<u32>,
    /// Median of the received samples (the mean of the two middle values
    /// for an even count, as SmokePing does).
    pub median_us: Option<u32>,
    /// 90th percentile, nearest-rank.
    pub p90_us: Option<u32>,
    pub max_us: Option<u32>,
}

impl RoundStats {
    pub fn from_samples(samples: &[Sample]) -> Self {
        let mut rtts: Vec<u32> = samples.iter().filter_map(Sample::rtt_us).collect();
        rtts.sort_unstable();
        let sent = u32::try_from(samples.len()).unwrap_or(u32::MAX);
        let received = u32::try_from(rtts.len()).unwrap_or(u32::MAX);
        Self {
            sent,
            received,
            min_us: rtts.first().copied(),
            median_us: median(&rtts),
            p90_us: nearest_rank(&rtts, 90),
            max_us: rtts.last().copied(),
        }
    }

    /// Lost fraction in `0.0..=1.0`; `0.0` for an empty round.
    pub fn loss_ratio(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        f64::from(self.sent - self.received) / f64::from(self.sent)
    }
}

fn median(sorted: &[u32]) -> Option<u32> {
    let n = sorted.len();
    match n {
        0 => None,
        _ if n % 2 == 1 => Some(sorted[n / 2]),
        _ => {
            let (a, b) = (u64::from(sorted[n / 2 - 1]), u64::from(sorted[n / 2]));
            u32::try_from((a + b) / 2).ok()
        }
    }
}

fn nearest_rank(sorted: &[u32], percentile: usize) -> Option<u32> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (percentile * sorted.len()).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(rtt_us: u32) -> Sample {
        Sample::Ok { rtt_us }
    }

    #[test]
    fn odd_count() {
        let s = RoundStats::from_samples(&[ok(30), ok(10), ok(20)]);
        assert_eq!(s.min_us, Some(10));
        assert_eq!(s.median_us, Some(20));
        assert_eq!(s.max_us, Some(30));
        assert_eq!(s.loss_ratio(), 0.0);
    }

    #[test]
    fn even_count_median_is_mean_of_middle_pair() {
        let s = RoundStats::from_samples(&[ok(10), ok(20), ok(30), ok(40)]);
        assert_eq!(s.median_us, Some(25));
    }

    #[test]
    fn p90_nearest_rank_of_twenty() {
        let samples: Vec<_> = (1..=20).map(|v| ok(v * 100)).collect();
        let s = RoundStats::from_samples(&samples);
        // rank = ceil(0.9 * 20) = 18
        assert_eq!(s.p90_us, Some(1800));
    }

    #[test]
    fn loss_and_errors_count_as_lost() {
        let s = RoundStats::from_samples(&[
            ok(10),
            Sample::Lost,
            Sample::Error(crate::SampleError::TimeExceeded),
            ok(20),
        ]);
        assert_eq!((s.sent, s.received), (4, 2));
        assert!((s.loss_ratio() - 0.5).abs() < f64::EPSILON);
        assert_eq!(s.median_us, Some(15));
    }

    #[test]
    fn all_lost() {
        let s = RoundStats::from_samples(&[Sample::Lost, Sample::Lost]);
        assert_eq!(s.median_us, None);
        assert_eq!(s.loss_ratio(), 1.0);
    }

    #[test]
    fn empty_round() {
        let s = RoundStats::from_samples(&[]);
        assert_eq!(s.sent, 0);
        assert_eq!(s.loss_ratio(), 0.0);
    }
}
