//! Rounds and samples (architecture doc §4.1 and §5.1).

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::timing::TimingSource;

/// A target whose host name has already been resolved for this round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// The name as configured or typed (host name or address literal).
    pub name: String,
    pub addr: IpAddr,
}

/// What one round should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundPlan {
    /// Samples per round, e.g. 20.
    pub count: u16,
    /// Window the samples are spread over, e.g. 20 s.
    pub spread: Duration,
    /// Per-sample timeout.
    pub timeout: Duration,
    /// Wall-clock start of the round.
    pub round_start: SystemTime,
}

impl RoundPlan {
    /// Offset of sample `index` from the round start: samples are evenly
    /// spaced, the first at offset zero.
    pub fn sample_offset(&self, index: u16) -> Duration {
        if self.count == 0 {
            return Duration::ZERO;
        }
        self.spread * u32::from(index) / u32::from(self.count)
    }
}

/// One request/response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sample {
    Ok { rtt_us: u32 },
    Lost,
    Error(SampleError),
}

impl Sample {
    pub fn rtt_us(&self) -> Option<u32> {
        match self {
            Self::Ok { rtt_us } => Some(*rtt_us),
            Self::Lost | Self::Error(_) => None,
        }
    }
}

/// Why a sample failed although something answered. Counts as loss for graphing,
/// but the cause is kept so "host unreachable" stays distinct from a timeout.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SampleError {
    #[error("destination unreachable (code {code})")]
    Unreachable { code: u8 },
    #[error("TTL expired in transit")]
    TimeExceeded,
    #[error("{0}")]
    Other(String),
}

/// Static facts about how a round was measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeMeta {
    pub resolved: IpAddr,
    pub timing: TimingSource,
    /// ICMP payload size in bytes.
    pub payload_size: u16,
}

/// A completed round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundResult {
    /// Wall-clock start (UTC).
    pub start: SystemTime,
    /// Samples in send order.
    pub samples: Vec<Sample>,
    pub meta: ProbeMeta,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_evenly_spread_from_zero() {
        let plan = RoundPlan {
            count: 4,
            spread: Duration::from_secs(20),
            timeout: Duration::from_secs(1),
            round_start: SystemTime::UNIX_EPOCH,
        };
        let offsets: Vec<_> = (0..4).map(|i| plan.sample_offset(i).as_secs()).collect();
        assert_eq!(offsets, [0, 5, 10, 15]);
    }

    #[test]
    fn zero_count_does_not_divide_by_zero() {
        let plan = RoundPlan {
            count: 0,
            spread: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            round_start: SystemTime::UNIX_EPOCH,
        };
        assert_eq!(plan.sample_offset(0), Duration::ZERO);
    }
}
