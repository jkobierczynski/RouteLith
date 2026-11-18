//! Platform-independent round logic on top of a platform `Engine`.

use std::sync::Arc;
use std::time::Duration;

use rl_core::{
    ProbeMeta, ResolvedTarget, RoundPlan, RoundResult, Sample, TimingBackend, TimingSource,
};
use tokio::sync::OnceCell;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until};

use super::IcmpConfig;
#[cfg(target_os = "linux")]
use super::linux::Engine;
#[cfg(windows)]
use super::windows::Engine;
use crate::packet::MIN_PAYLOAD;
use crate::{ProbeError, RateLimiter};

/// Lazily opened engines, one per address family.
#[derive(Debug, Default)]
pub(super) struct Engines {
    v4: OnceCell<Arc<Engine>>,
    v6: OnceCell<Arc<Engine>>,
}

pub(super) async fn run(
    engines: &Engines,
    config: IcmpConfig,
    limiter: Option<&Arc<RateLimiter>>,
    target: &ResolvedTarget,
    plan: RoundPlan,
) -> Result<RoundResult, ProbeError> {
    let dest = target.addr;
    let v6 = dest.is_ipv6();
    let payload = usize::from(config.payload_size).max(MIN_PAYLOAD);
    let cell = if v6 { &engines.v6 } else { &engines.v4 };
    let engine = cell
        .get_or_try_init(|| async { Engine::open(v6, payload).map(Arc::new) })
        .await?
        .clone();

    let t0 = Instant::now();
    let mut tasks = JoinSet::new();
    for i in 0..plan.count {
        let engine = Arc::clone(&engine);
        let at = t0 + plan.sample_offset(i);
        let timeout = plan.timeout;
        let limiter = limiter.cloned();
        tasks.spawn(async move {
            sleep_until(at).await;
            if let Some(l) = limiter {
                l.acquire().await;
            }
            (i, engine.sample(dest, timeout).await)
        });
    }

    let mut samples = vec![Sample::Lost; usize::from(plan.count)];
    let mut backend = engine.preferred_backend();
    while let Some(joined) = tasks.join_next().await {
        let (i, (sample, used)) = joined.map_err(|e| ProbeError::Io(std::io::Error::other(e)))?;
        if precision(used) > precision(backend) {
            backend = used;
        }
        samples[usize::from(i)] = sample;
    }

    Ok(RoundResult {
        start: plan.round_start,
        samples,
        meta: ProbeMeta {
            resolved: dest,
            timing: TimingSource::new(backend),
            payload_size: u16::try_from(payload).unwrap_or(u16::MAX),
        },
    })
}

/// A round reports the least precise backend any of its samples used.
fn precision(b: TimingBackend) -> u32 {
    TimingSource::new(b).precision_us
}

/// A successful sample, RTT saturated to whole microseconds.
pub(super) fn ok_sample(rtt: Duration) -> Sample {
    Sample::Ok {
        rtt_us: u32::try_from(rtt.as_micros()).unwrap_or(u32::MAX),
    }
}
