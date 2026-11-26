//! ICMP path tracing (architecture doc §8.3, decisions §21.9 P1–P4).
//!
//! A [`Tracer`] sends one echo request with a given TTL to one destination
//! and reports who answered: a router on the path (Time Exceeded), the
//! destination (echo reply), an Unreachable, or nothing. Linux uses an
//! unprivileged ping socket per trace and reads Time Exceeded from the
//! socket's error queue; Windows uses the ICMP helper API with an APC thread.
//! Neither needs root or Administrator.
//!
//! A [`Session`] plans sweeps (one probe per TTL, spread over the interval)
//! and [`HopStats`] summarises them per TTL, as `routelith trace` shows.
#![forbid(unsafe_code)]

mod stats;
mod sweep;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

use std::fmt;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rl_core::TimingBackend;

pub use stats::{HopStats, Responder, TraceStats};
pub use sweep::{Session, Sweep, SweepPlan, run_sweep};

/// A boxed, `Send` future, so [`Tracer`] stays object-safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Payload bytes after the ICMP header: an 8-byte nonce, then
/// [`PAYLOAD_TAG`] so a trace is recognisable in a capture (risk R6).
pub const PAYLOAD_SIZE: usize = 32;
/// Marker in every trace probe's payload.
pub const PAYLOAD_TAG: &[u8] = b"routelith-trace";

/// What one probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A router on the path sent Time Exceeded.
    TimeExceeded { from: IpAddr, rtt: Duration },
    /// The destination answered.
    Reply { from: IpAddr, rtt: Duration },
    /// Destination Unreachable, from a router or the destination.
    Unreachable {
        from: Option<IpAddr>,
        /// ICMP code (Linux) or the `IP_DEST_*` status less
        /// `IP_DEST_NET_UNREACHABLE` (Windows).
        code: u8,
        rtt: Duration,
    },
    /// Nothing came back within the timeout.
    Lost,
    /// The probe could not be sent from this host.
    SendFailed(String),
}

impl Outcome {
    /// The host that answered, if any.
    pub fn responder(&self) -> Option<IpAddr> {
        match self {
            Self::TimeExceeded { from, .. } | Self::Reply { from, .. } => Some(*from),
            Self::Unreachable { from, .. } => *from,
            Self::Lost | Self::SendFailed(_) => None,
        }
    }

    pub fn rtt(&self) -> Option<Duration> {
        match self {
            Self::TimeExceeded { rtt, .. }
            | Self::Reply { rtt, .. }
            | Self::Unreachable { rtt, .. } => Some(*rtt),
            Self::Lost | Self::SendFailed(_) => None,
        }
    }

    /// Whether this answer ends the path: an echo reply or an Unreachable.
    pub fn ends_path(&self) -> bool {
        matches!(self, Self::Reply { .. } | Self::Unreachable { .. })
    }
}

/// One probe's result and how its RTT was timed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub outcome: Outcome,
    pub timing: TimingBackend,
}

/// Sends TTL-limited echo requests to one destination.
pub trait Tracer: Send + Sync + fmt::Debug {
    fn dest(&self) -> IpAddr;

    /// The timing backend the probes normally use.
    fn timing(&self) -> TimingBackend;

    /// Send one probe with `ttl` and wait up to `timeout` for an answer.
    /// Probes may overlap.
    fn probe(&self, ttl: u8, timeout: Duration) -> BoxFuture<'_, ProbeResult>;
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TraceError {
    /// As `rl_probe::ProbeError::PingSocketNotPermitted`.
    #[error(transparent)]
    Probe(#[from] rl_probe::ProbeError),
    #[error("path tracing is not supported on this platform yet")]
    Unsupported,
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Open a tracer for `dest`. On Linux this must run inside a Tokio runtime.
pub fn open(dest: IpAddr) -> Result<Arc<dyn Tracer>, TraceError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Arc::new(linux::LinuxTracer::open(dest)?))
    }
    #[cfg(windows)]
    {
        Ok(Arc::new(windows::WindowsTracer::open(dest)?))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = dest;
        Err(TraceError::Unsupported)
    }
}

/// The payload after the nonce: the tag, then a fill pattern.
#[cfg(any(target_os = "linux", windows))]
fn payload_fill(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = PAYLOAD_TAG.get(i).copied().unwrap_or((i % 256) as u8);
    }
}
