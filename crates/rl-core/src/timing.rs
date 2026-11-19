//! How a sample's round-trip time was measured (architecture doc §10.3).

use std::fmt;

/// The clock source behind an RTT measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimingBackend {
    /// Linux ping socket; receive time from kernel `SO_TIMESTAMPNS`,
    /// send time taken just before `sendto`.
    LinuxKernelTimestamp,
    /// Linux ping socket; both ends timed in user space with the monotonic clock
    /// (used when kernel timestamps are unavailable or implausible).
    LinuxMonotonic,
    /// Windows `IcmpSendEcho2Ex` / `Icmp6SendEcho2`, timed with QPC around the call.
    WindowsIcmpApi,
    /// Monotonic clock read in user space around a socket operation
    /// (TCP connect, DNS query, HTTP phases). Includes scheduler wake-up delay.
    Monotonic,
}

impl TimingBackend {
    /// Stable one-byte code for storage. Never reuse a retired code.
    pub fn code(self) -> u8 {
        match self {
            Self::LinuxKernelTimestamp => 1,
            Self::LinuxMonotonic => 2,
            Self::WindowsIcmpApi => 3,
            Self::Monotonic => 4,
        }
    }

    /// Inverse of [`code`](Self::code); `None` for unknown codes.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::LinuxKernelTimestamp),
            2 => Some(Self::LinuxMonotonic),
            3 => Some(Self::WindowsIcmpApi),
            4 => Some(Self::Monotonic),
            _ => None,
        }
    }

    /// Short human-readable name, used in CLI output and the UI badge.
    pub fn describe(self) -> &'static str {
        match self {
            Self::LinuxKernelTimestamp => "kernel timestamps (ping socket)",
            Self::LinuxMonotonic => "user-space monotonic clock (ping socket)",
            Self::WindowsIcmpApi => "Windows ICMP API, QPC-timed",
            Self::Monotonic => "user-space monotonic clock",
        }
    }
}

/// The timing source of a round, with its nominal precision.
///
/// The precision is the documented expectation for the backend, not a
/// per-round measurement. Calibration (risk R1) replaces these numbers with
/// measured ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingSource {
    pub backend: TimingBackend,
    /// Expected measurement error, ± microseconds.
    pub precision_us: u32,
}

impl TimingSource {
    pub fn new(backend: TimingBackend) -> Self {
        let precision_us = match backend {
            TimingBackend::LinuxKernelTimestamp => 50,
            TimingBackend::LinuxMonotonic => 100,
            TimingBackend::WindowsIcmpApi => 500,
            // §10.3 puts socket-timed probes at ±0.1 to 1 ms.
            TimingBackend::Monotonic => 200,
        };
        Self {
            backend,
            precision_us,
        }
    }
}

impl fmt::Display for TimingSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, precision ±{:.2} ms",
            self.backend.describe(),
            f64::from(self.precision_us) / 1000.0
        )
    }
}
