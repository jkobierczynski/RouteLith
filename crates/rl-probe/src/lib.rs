//! The Probe trait and its ICMP, TCP, UDP, DNS and HTTP implementations.
//!
//! ICMP (Linux ping sockets, the Windows ICMP API) and TCP connect time so far.
#![forbid(unsafe_code)]

pub mod calibration;
pub mod icmp;
pub mod packet;
pub mod rate;
pub mod tcp;

use std::future::Future;
use std::io;
use std::pin::Pin;

use rl_core::{ResolvedTarget, RoundPlan, RoundResult};

pub use icmp::{IcmpConfig, IcmpProbe, check_permission};
pub use rate::RateLimiter;
pub use tcp::{TcpConfig, TcpProbe};

/// A boxed, `Send` future, so `Probe` stays object-safe.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The measurement methods Routelith knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProbeKind {
    Icmp,
    Tcp,
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
    /// The OS refused the ICMP socket. Usually the user's group is outside
    /// `net.ipv4.ping_group_range`, but a security policy can also deny it.
    #[error(
        "cannot open an ICMP socket ({0}); the usual cause is that this user's group is outside \
         net.ipv4.ping_group_range (for example: sysctl -w net.ipv4.ping_group_range='0 2147483647'), \
         but a security policy such as seccomp or SELinux can also deny it"
    )]
    PingSocketNotPermitted(io::Error),
    #[error("ICMP probing is not supported on this platform yet")]
    Unsupported,
    #[error(transparent)]
    Io(#[from] io::Error),
}
