//! The stored form of a round (architecture doc §5.1).

use std::net::IpAddr;
use std::time::UNIX_EPOCH;

use rl_core::{RoundResult, Sample, SampleError, TimingBackend};

/// Flag: the wall clock stepped (NTP step, sleep/resume) near this round.
pub const FLAG_CLOCK_STEP: u8 = 0x01;

/// Counts of failed samples by cause. All of them also count as loss.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ErrorCounts {
    pub unreachable: u16,
    pub time_exceeded: u16,
    pub send_failed: u16,
    pub other: u16,
}

impl ErrorCounts {
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }

    pub fn total(&self) -> u32 {
        u32::from(self.unreachable)
            + u32::from(self.time_exceeded)
            + u32::from(self.send_failed)
            + u32::from(self.other)
    }
}

/// One round as stored: sorted RTTs plus enough to recover loss and causes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRound {
    /// Round start, Unix milliseconds (UTC).
    pub ts_ms: i64,
    /// Samples sent.
    pub sent: u16,
    /// RTTs of the replies, ascending, microseconds. `sent - len` were lost.
    pub rtts_us: Vec<u32>,
    pub errors: ErrorCounts,
    /// Address measured. Stored only when it changes, filled forward on read.
    pub resolved: Option<IpAddr>,
    /// Stored only when it changes, filled forward on read.
    pub timing: Option<TimingBackend>,
    /// `FLAG_*` bits.
    pub flags: u8,
}

impl StoredRound {
    /// Lost and errored samples.
    pub fn loss(&self) -> u16 {
        let received = u16::try_from(self.rtts_us.len()).unwrap_or(u16::MAX);
        self.sent.saturating_sub(received)
    }

    /// Loss as a fraction in `0.0..=1.0`; `0.0` for an empty round.
    pub fn loss_ratio(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            f64::from(self.loss()) / f64::from(self.sent)
        }
    }

    /// Convert a probe's round. RTTs are sorted; sample order is not kept.
    ///
    /// Fails if the round has more samples than a stored round can count
    /// (65,535).
    pub fn from_result(r: &RoundResult, flags: u8) -> Result<Self, crate::StoreError> {
        let sent = u16::try_from(r.samples.len())
            .map_err(|_| crate::StoreError::InvalidRound("more than 65,535 samples"))?;
        let mut rtts_us: Vec<u32> = r.samples.iter().filter_map(Sample::rtt_us).collect();
        rtts_us.sort_unstable();
        let mut errors = ErrorCounts::default();
        for s in &r.samples {
            if let Sample::Error(e) = s {
                let slot = match e {
                    SampleError::Unreachable { .. } => &mut errors.unreachable,
                    SampleError::TimeExceeded => &mut errors.time_exceeded,
                    SampleError::SendFailed(_) => &mut errors.send_failed,
                    _ => &mut errors.other,
                };
                *slot = slot.saturating_add(1);
            }
        }
        let ts_ms = match r.start.duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
            // Before the epoch: round down, so -0.5 ms is -1, not 0.
            Err(e) => {
                let d = e.duration();
                let ms = d.as_millis() + u128::from(d.subsec_nanos() % 1_000_000 != 0);
                -i64::try_from(ms).unwrap_or(i64::MAX)
            }
        };
        Ok(Self {
            ts_ms,
            sent,
            rtts_us,
            errors,
            resolved: Some(r.meta.resolved),
            timing: Some(r.meta.timing.backend),
            flags,
        })
    }

    /// Whether this round is well-formed enough to store.
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let day = crate::layout::day_of(self.ts_ms);
        if !(crate::layout::MIN_DAY..=crate::layout::MAX_DAY).contains(&day) {
            return Err("timestamp outside the years 0000 to 9999");
        }
        if self.rtts_us.len() > usize::from(self.sent) {
            return Err("more RTTs than samples sent");
        }
        if !self.rtts_us.is_sorted() {
            return Err("RTTs are not sorted");
        }
        if self.errors.total() > u32::from(self.loss()) {
            return Err("more errors than lost samples");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_core::{ProbeMeta, TimingSource};
    use std::time::Duration;

    #[test]
    fn from_result_sorts_and_counts() {
        let r = RoundResult {
            start: UNIX_EPOCH + Duration::from_secs(300),
            samples: vec![
                Sample::Ok { rtt_us: 30 },
                Sample::Lost,
                Sample::Ok { rtt_us: 10 },
                Sample::Error(SampleError::TimeExceeded),
            ],
            meta: ProbeMeta {
                resolved: "192.0.2.1".parse().unwrap(),
                timing: TimingSource::new(TimingBackend::LinuxKernelTimestamp),
                payload_size: 56,
            },
            http: None,
        };
        let s = StoredRound::from_result(&r, 0).unwrap();
        assert_eq!(s.ts_ms, 300_000);
        assert_eq!(s.sent, 4);
        assert_eq!(s.rtts_us, [10, 30]);
        assert_eq!(s.loss(), 2);
        assert_eq!(s.errors.time_exceeded, 1);
        assert!(s.check().is_ok());
    }
}
