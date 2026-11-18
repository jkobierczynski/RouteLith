//! ICMP echo probe (architecture doc §4.2).

#[cfg(any(target_os = "linux", windows))]
mod round;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

use rl_core::{ResolvedTarget, RoundPlan, RoundResult};

use crate::packet::DEFAULT_PAYLOAD;
use crate::{BoxFuture, Probe, ProbeError, ProbeKind};

/// Check that this process may send ICMP echo for one address family,
/// by opening and closing the socket or handle a round would use.
pub fn check_permission(v6: bool) -> Result<(), ProbeError> {
    #[cfg(target_os = "linux")]
    {
        use std::io::ErrorKind;
        rl_sys::linux::PingSocket::open(v6)
            .map(drop)
            .map_err(|e| match e.kind() {
                ErrorKind::PermissionDenied => ProbeError::PingSocketNotPermitted,
                _ => ProbeError::Io(e),
            })
    }
    #[cfg(windows)]
    {
        rl_sys::windows::IcmpHandle::open(v6)
            .map(drop)
            .map_err(ProbeError::Io)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = v6;
        Err(ProbeError::Unsupported)
    }
}

/// ICMP probe options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpConfig {
    /// Payload bytes after the 8-byte ICMP header (at least 8, for the nonce).
    pub payload_size: u16,
}

impl Default for IcmpConfig {
    fn default() -> Self {
        Self {
            payload_size: DEFAULT_PAYLOAD,
        }
    }
}

/// ICMP echo probe. Holds at most one OS socket/handle per address family,
/// shared by every round and target (one demultiplexer per family).
#[derive(Debug, Default)]
pub struct IcmpProbe {
    config: IcmpConfig,
    limiter: Option<std::sync::Arc<crate::RateLimiter>>,
    #[cfg(any(target_os = "linux", windows))]
    engines: round::Engines,
}

impl IcmpProbe {
    // On platforms without an engine `config` is the only field.
    #[allow(clippy::needless_update)]
    pub fn new(config: IcmpConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Share a packets-per-second ceiling with other probes.
    pub fn with_rate_limiter(mut self, limiter: std::sync::Arc<crate::RateLimiter>) -> Self {
        self.limiter = Some(limiter);
        self
    }

    pub fn config(&self) -> IcmpConfig {
        self.config
    }

    #[cfg(any(target_os = "linux", windows))]
    async fn round(
        &self,
        target: &ResolvedTarget,
        plan: RoundPlan,
    ) -> Result<RoundResult, ProbeError> {
        round::run(
            &self.engines,
            self.config,
            self.limiter.as_ref(),
            target,
            plan,
        )
        .await
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    async fn round(
        &self,
        _target: &ResolvedTarget,
        _plan: RoundPlan,
    ) -> Result<RoundResult, ProbeError> {
        Err(ProbeError::Unsupported)
    }
}

impl Probe for IcmpProbe {
    fn kind(&self) -> ProbeKind {
        ProbeKind::Icmp
    }

    fn run_round<'a>(
        &'a self,
        target: &'a ResolvedTarget,
        plan: RoundPlan,
    ) -> BoxFuture<'a, Result<RoundResult, ProbeError>> {
        Box::pin(self.round(target, plan))
    }
}
