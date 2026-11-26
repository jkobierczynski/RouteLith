//! Windows tracer: the ICMP helper API on one shared APC thread (§21.9 P3).

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rl_core::TimingBackend;
use rl_sys::wintrace::{TraceOutcome, TraceRequest, TraceWorker};
use tokio::sync::oneshot;

use crate::{BoxFuture, Outcome, PAYLOAD_SIZE, ProbeResult, Tracer, payload_fill};

/// First `IP_DEST_*_UNREACHABLE` status (`IP_DEST_NET_UNREACHABLE`).
const IP_DEST_NET_UNREACHABLE: u32 = 11002;
/// Extra wait beyond the API's own timeout before a probe counts as lost.
const GRACE: Duration = Duration::from_secs(1);

/// The worker every trace in the process shares.
fn worker() -> std::io::Result<Arc<TraceWorker>> {
    static WORKER: OnceLock<Result<Arc<TraceWorker>, String>> = OnceLock::new();
    WORKER
        .get_or_init(|| {
            TraceWorker::start()
                .map(Arc::new)
                .map_err(|e| e.to_string())
        })
        .clone()
        .map_err(std::io::Error::other)
}

#[derive(Debug)]
pub(crate) struct WindowsTracer {
    dest: IpAddr,
    worker: Arc<TraceWorker>,
    payload: Arc<[u8]>,
}

impl WindowsTracer {
    pub(crate) fn open(dest: IpAddr) -> Result<Self, crate::TraceError> {
        let worker = worker()?;
        if !worker.supports(dest.is_ipv6()) {
            return Err(crate::TraceError::Io(std::io::Error::other(
                "cannot open an ICMP handle for this address family",
            )));
        }
        // No nonce on Windows: the API matches replies itself.
        let mut payload = vec![0u8; PAYLOAD_SIZE];
        payload_fill(&mut payload);
        Ok(Self {
            dest,
            worker,
            payload: payload.into(),
        })
    }

    async fn probe_inner(&self, ttl: u8, timeout: Duration) -> ProbeResult {
        let (tx, rx) = oneshot::channel();
        self.worker.submit(TraceRequest {
            dest: self.dest,
            ttl,
            payload: Arc::clone(&self.payload),
            timeout,
            done: Box::new(move |outcome| {
                let _ = tx.send(outcome);
            }),
        });
        let outcome = match tokio::time::timeout(timeout + GRACE, rx).await {
            Ok(Ok(TraceOutcome::Reply { from, elapsed })) => Outcome::Reply { from, rtt: elapsed },
            Ok(Ok(TraceOutcome::TtlExpired { from, elapsed })) => {
                Outcome::TimeExceeded { from, rtt: elapsed }
            }
            Ok(Ok(TraceOutcome::Unreachable {
                from,
                status,
                elapsed,
            })) => Outcome::Unreachable {
                from,
                code: status
                    .checked_sub(IP_DEST_NET_UNREACHABLE)
                    .and_then(|c| u8::try_from(c).ok())
                    .unwrap_or(u8::MAX),
                rtt: elapsed,
            },
            Ok(Ok(TraceOutcome::SendError(e))) => Outcome::SendFailed(e.to_string()),
            Ok(Ok(TraceOutcome::TimedOut | TraceOutcome::Failed { .. })) | Ok(Err(_)) | Err(_) => {
                Outcome::Lost
            }
        };
        ProbeResult {
            outcome,
            timing: TimingBackend::WindowsIcmpApi,
        }
    }
}

impl Tracer for WindowsTracer {
    fn dest(&self) -> IpAddr {
        self.dest
    }

    fn timing(&self) -> TimingBackend {
        TimingBackend::WindowsIcmpApi
    }

    fn probe(&self, ttl: u8, timeout: Duration) -> BoxFuture<'_, ProbeResult> {
        Box::pin(self.probe_inner(ttl, timeout))
    }
}
