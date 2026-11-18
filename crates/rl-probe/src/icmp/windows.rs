//! Windows engine: one ICMP handle per family; each sample is a synchronous
//! `IcmpSendEcho2Ex` / `Icmp6SendEcho2` call on Tokio's blocking pool, timed
//! with QPC around the call.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rl_core::{Sample, SampleError, TimingBackend};
use rl_sys::windows::{EchoOutcome, IcmpHandle};

use super::round::ok_sample;
use crate::ProbeError;

const TTL: u8 = 128;
/// First `IP_DEST_*_UNREACHABLE` status (`IP_DEST_NET_UNREACHABLE`).
const IP_DEST_NET_UNREACHABLE: u32 = 11002;

#[derive(Debug)]
pub(super) struct Engine {
    handle: Arc<IcmpHandle>,
    payload: Arc<[u8]>,
}

impl Engine {
    pub(super) fn open(v6: bool, payload_size: usize) -> Result<Self, ProbeError> {
        let handle = IcmpHandle::open(v6)?;
        let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();
        Ok(Self {
            handle: Arc::new(handle),
            payload: payload.into(),
        })
    }

    pub(super) fn preferred_backend(&self) -> TimingBackend {
        TimingBackend::WindowsIcmpApi
    }

    pub(super) async fn sample(&self, dest: IpAddr, timeout: Duration) -> (Sample, TimingBackend) {
        let handle = Arc::clone(&self.handle);
        let payload = Arc::clone(&self.payload);
        let outcome =
            tokio::task::spawn_blocking(move || handle.echo(dest, &payload, TTL, timeout)).await;
        let sample = match outcome {
            Ok(Ok(EchoOutcome::Reply { elapsed, .. })) => ok_sample(elapsed),
            Ok(Ok(EchoOutcome::TimedOut)) => Sample::Lost,
            Ok(Ok(EchoOutcome::TtlExpired)) => Sample::Error(SampleError::TimeExceeded),
            Ok(Ok(EchoOutcome::Unreachable { status })) => {
                Sample::Error(SampleError::Unreachable {
                    code: status
                        .checked_sub(IP_DEST_NET_UNREACHABLE)
                        .and_then(|c| u8::try_from(c).ok())
                        .unwrap_or(u8::MAX),
                })
            }
            Ok(Ok(EchoOutcome::Failed { status })) => {
                Sample::Error(SampleError::Other(format!("IP status {status}")))
            }
            Ok(Err(e)) => Sample::Error(SampleError::SendFailed(e.to_string())),
            Err(e) => Sample::Error(SampleError::Other(e.to_string())),
        };
        (sample, TimingBackend::WindowsIcmpApi)
    }
}
