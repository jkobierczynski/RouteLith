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
        // Wide intermediate: spread × index can exceed Duration's range.
        let nanos = self.spread.as_nanos() * u128::from(index) / u128::from(self.count);
        let sub = (nanos % 1_000_000_000) as u32;
        match u64::try_from(nanos / 1_000_000_000) {
            Ok(secs) => Duration::new(secs, sub),
            Err(_) => Duration::MAX,
        }
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
    /// The host answered with a refusal (TCP RST): reachable, but the port
    /// is closed. The time until the refusal is kept (§4.3).
    #[error("connection refused after {:.3} ms", f64::from(*rtt_us) / 1000.0)]
    Refused { rtt_us: u32 },
    /// A DNS server answered, but not with the expected rcode or answer set.
    #[error("unexpected DNS answer: {0}")]
    DnsMismatch(String),
    /// An HTTP status outside the expected ranges.
    #[error("HTTP status {status}")]
    HttpStatus { status: u16 },
    /// The response body did not match the expected pattern.
    #[error("response body does not match body_regex")]
    BodyMismatch,
    /// The TLS handshake failed (certificate, protocol).
    #[error("TLS: {0}")]
    Tls(String),
    /// The request never left this host (socket error, resource limit).
    #[error("send failed: {0}")]
    SendFailed(String),
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
    /// HTTP detail (phase timings, certificate); `None` for other probes.
    pub http: Option<HttpRound>,
}

/// What an HTTP round measured beyond each sample's selected metric (§4.6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpRound {
    /// Phase timings per sample, in send order; `None` for a sample that
    /// got no response.
    pub phases: Vec<Option<PhaseTimings>>,
    /// Expiry (`notAfter`) of the server certificate, from the last sample
    /// that completed a TLS handshake.
    pub cert_not_after: Option<SystemTime>,
}

/// Where the time of one HTTP request went, in microseconds. `ttfb` and
/// `total` count from the start of the TCP connect (like curl's
/// `time_starttransfer` and `time_total`); `connect` and `tls` are the
/// handshakes alone. Name resolution happens once per round, before the
/// samples, so it is not a phase here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseTimings {
    pub connect_us: u32,
    /// `None` for plain HTTP.
    pub tls_us: Option<u32>,
    pub ttfb_us: u32,
    pub total_us: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_beyond_u64_nanoseconds_stay_exact() {
        let plan = RoundPlan {
            count: 2,
            spread: Duration::from_secs(40_000_000_000),
            timeout: Duration::from_secs(1),
            round_start: std::time::UNIX_EPOCH,
        };
        assert_eq!(plan.sample_offset(1), Duration::from_secs(20_000_000_000));
    }

    #[test]
    fn an_offset_of_exactly_u64_max_seconds_is_not_clamped() {
        let plan = RoundPlan {
            count: 1,
            spread: Duration::from_secs(u64::MAX),
            timeout: Duration::from_secs(1),
            round_start: std::time::UNIX_EPOCH,
        };
        assert_eq!(plan.sample_offset(1), Duration::from_secs(u64::MAX));
        assert_eq!(plan.sample_offset(2), Duration::MAX);
    }

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
