//! The Probe trait and its ICMP, TCP, UDP, DNS and HTTP implementations.
//!
//! M0 has ICMP only: Linux ping sockets and the Windows ICMP API.
#![forbid(unsafe_code)]

pub mod calibration;
pub mod icmp;
pub mod packet;
pub mod rate;

use std::future::Future;
use std::io;
use std::pin::Pin;

use rl_core::{ResolvedTarget, RoundPlan, RoundResult};

pub use icmp::{IcmpConfig, IcmpProbe, check_permission};
pub use rate::RateLimiter;

/// A boxed, `Send` future, so `Probe` stays object-safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The measurement methods Routelith knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProbeKind {
    Icmp,
}

/// One measurement method (architecture doc §4.1).
pub trait Probe: Send + Sync {
    fn kind(&self) -> ProbeKind;

    /// Run one round: `plan.count` samples spread over `plan.spread`.
    /// Samples come back in send order.
    fn run_round<'a>(
        &'a self,
        target: &'a ResolvedTarget,
        plan: RoundPlan,
    ) -> BoxFuture<'a, Result<RoundResult, ProbeError>>;
}

/// Failure of a whole round (individual losses are samples, not errors).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProbeError {
    #[error(
        "unprivileged ICMP is not permitted: add this user's group to net.ipv4.ping_group_range \
         (for example: sysctl -w net.ipv4.ping_group_range='0 2147483647')"
    )]
    PingSocketNotPermitted,
    #[error("ICMP probing is not supported on this platform yet")]
    Unsupported,
    #[error(transparent)]
    Io(#[from] io::Error),
}
