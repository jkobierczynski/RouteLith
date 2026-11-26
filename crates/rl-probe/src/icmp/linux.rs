//! Linux engine: one shared ping socket per family, a reader task that
//! demultiplexes replies by sequence number, and kernel receive timestamps.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, SystemTimeError};

use rl_core::{Sample, SampleError, TimingBackend};
use rl_sys::linux::PingSocket;
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use super::round::ok_sample;
use crate::ProbeError;
use crate::packet::{build_echo_request, parse_echo_reply};

/// Kernel timestamps are trusted only if they are no later than the user-space
/// receive time plus this margin (guards against wall-clock steps mid-sample).
const KERNEL_TS_SLACK: Duration = Duration::from_millis(1);

#[derive(Debug)]
pub(super) struct Engine {
    shared: Arc<Shared>,
    reader: AbortHandle,
    payload_size: usize,
    next_seq: AtomicU16,
    nonce_counter: AtomicU64,
    nonce_seed: RandomState,
}

#[derive(Debug)]
struct Shared {
    sock: AsyncFd<PingSocket>,
    pending: Mutex<HashMap<u16, Pending>>,
}

#[derive(Debug)]
struct Pending {
    nonce: u64,
    dest: IpAddr,
    reply: oneshot::Sender<Rx>,
}

#[derive(Debug)]
struct Rx {
    kernel: Option<SystemTime>,
    /// Wall clock and monotonic clock read together when the reply was handled.
    wall: SystemTime,
    user: Instant,
}

/// Removes a pending request when its sample ends for any reason, including
/// cancellation of the sample task. Only an entry that still carries this
/// request's nonce is removed, so a reused sequence number is left alone.
struct PendingGuard<'a> {
    shared: &'a Shared,
    seq: u16,
    nonce: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        let mut pending = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if pending
            .get(&self.seq)
            .is_some_and(|p| p.nonce == self.nonce)
        {
            pending.remove(&self.seq);
        }
    }
}

impl Engine {
    pub(super) fn open(v6: bool, payload_size: usize) -> Result<Self, ProbeError> {
        let sock = PingSocket::open(v6).map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => ProbeError::PingSocketNotPermitted(e),
            _ => ProbeError::Io(e),
        })?;
        let shared = Arc::new(Shared {
            sock: sock.into_async()?,
            pending: Mutex::new(HashMap::new()),
        });
        let reader = tokio::spawn(read_loop(Arc::clone(&shared))).abort_handle();
        Ok(Self {
            shared,
            reader,
            payload_size,
            next_seq: AtomicU16::new(0),
            nonce_counter: AtomicU64::new(0),
            nonce_seed: RandomState::new(),
        })
    }

    pub(super) fn preferred_backend(&self) -> TimingBackend {
        if self.shared.sock.get_ref().has_kernel_timestamps() {
            TimingBackend::LinuxKernelTimestamp
        } else {
            TimingBackend::LinuxMonotonic
        }
    }

    /// One echo. `sent` is called once the request has left (or failed to).
    pub(super) async fn sample(
        &self,
        dest: IpAddr,
        timeout: Duration,
        sent: impl FnOnce(),
    ) -> (Sample, TimingBackend) {
        let nonce = self
            .nonce_seed
            .hash_one(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = oneshot::channel();
        let Some(seq) = self.register(Pending {
            nonce,
            dest,
            reply: tx,
        }) else {
            let err = SampleError::SendFailed("too many requests in flight".into());
            return (Sample::Error(err), self.preferred_backend());
        };
        let _guard = PendingGuard {
            shared: &self.shared,
            seq,
            nonce,
        };
        let v6 = self.shared.sock.get_ref().is_v6();
        let packet = build_echo_request(v6, 0, seq, nonce, self.payload_size);

        let result = self.send(&packet, dest).await;
        sent();
        let (tx_wall, tx_user) = match result {
            Ok(times) => times,
            Err(e) => {
                return (
                    Sample::Error(SampleError::SendFailed(e.to_string())),
                    self.preferred_backend(),
                );
            }
        };

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(rx)) => {
                let (rtt, backend) = select_rtt(
                    rx.kernel.map(|k| k.duration_since(tx_wall)),
                    rx.wall.duration_since(tx_wall),
                    rx.user.saturating_duration_since(tx_user),
                );
                (ok_sample(rtt), backend)
            }
            _ => (Sample::Lost, self.preferred_backend()),
        }
    }

    /// Send, recording wall-clock and monotonic time immediately before `sendto`.
    async fn send(&self, packet: &[u8], dest: IpAddr) -> io::Result<(SystemTime, Instant)> {
        loop {
            let mut guard = self.shared.sock.writable().await?;
            let mut times = None;
            let result = guard.try_io(|s| {
                times = Some((SystemTime::now(), Instant::now()));
                s.get_ref().send_to(packet, dest)
            });
            match result {
                Ok(Ok(_)) => {
                    return times.ok_or_else(|| io::Error::other("send time not recorded"));
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    /// Reserve a free sequence number for `pending`.
    fn register(&self, pending: Pending) -> Option<u16> {
        let mut map = self
            .shared
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for _ in 0..=u16::MAX {
            let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
            if let std::collections::hash_map::Entry::Vacant(slot) = map.entry(seq) {
                slot.insert(pending);
                return Some(seq);
            }
        }
        None
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Pick the RTT for one reply.
///
/// The kernel receive timestamp is measured against the wall-clock send time, so
/// it is only trusted while the wall clock and the monotonic clock advanced
/// alike between send and receive (no NTP step in between) and it is no later
/// than the user-space receive time. Otherwise the monotonic RTT is used.
pub fn select_rtt(
    kernel_rtt: Option<Result<Duration, SystemTimeError>>,
    wall_rtt: Result<Duration, SystemTimeError>,
    user_rtt: Duration,
) -> (Duration, TimingBackend) {
    let clocks_agree = wall_rtt.is_ok_and(|w| w.abs_diff(user_rtt) <= KERNEL_TS_SLACK);
    match kernel_rtt {
        Some(Ok(k)) if clocks_agree && k <= user_rtt + KERNEL_TS_SLACK => {
            (k, TimingBackend::LinuxKernelTimestamp)
        }
        _ => (user_rtt, TimingBackend::LinuxMonotonic),
    }
}

async fn read_loop(shared: Arc<Shared>) {
    let v6 = shared.sock.get_ref().is_v6();
    let mut buf = vec![0u8; 65_536];
    loop {
        let Ok(mut guard) = shared.sock.readable().await else {
            return;
        };
        loop {
            match guard.try_io(|s| s.get_ref().recv(&mut buf)) {
                Ok(Ok(received)) => {
                    let (wall, user) = (SystemTime::now(), Instant::now());
                    let Some(reply) = parse_echo_reply(v6, &buf[..received.len]) else {
                        continue;
                    };
                    let mut pending = shared
                        .pending
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    let matches = pending.get(&reply.seq).is_some_and(|p| {
                        Some(p.nonce) == reply.nonce
                            && received.from.is_none_or(|from| from == p.dest)
                    });
                    if let Some(p) = matches.then(|| pending.remove(&reply.seq)).flatten() {
                        let _ = p.reply.send(Rx {
                            kernel: received.kernel_time,
                            wall,
                            user,
                        });
                    }
                }
                // Transient errors (e.g. ICMP errors queued on the socket) are not fatal.
                Ok(Err(_)) => continue,
                Err(_would_block) => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn before(d: Duration) -> Result<Duration, SystemTimeError> {
        // A SystemTimeError for "receive time is `d` before send time".
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        (t - d).duration_since(t)
    }

    #[test]
    fn stable_clocks_use_the_kernel_timestamp() {
        let (rtt, backend) = select_rtt(Some(Ok(10 * MS)), Ok(10 * MS + MS / 5), 10 * MS + MS / 5);
        assert_eq!(
            (rtt, backend),
            (10 * MS, TimingBackend::LinuxKernelTimestamp)
        );
    }

    #[test]
    fn backward_clock_step_falls_back_to_monotonic() {
        // 200 ms reply, wall clock stepped back 100 ms in between: the kernel
        // value (100 ms) looks plausible on its own but must not be used.
        let (rtt, backend) = select_rtt(Some(Ok(100 * MS)), Ok(100 * MS), 200 * MS);
        assert_eq!((rtt, backend), (200 * MS, TimingBackend::LinuxMonotonic));
    }

    #[test]
    fn forward_clock_step_falls_back_to_monotonic() {
        let (rtt, backend) = select_rtt(Some(Ok(1100 * MS)), Ok(1100 * MS), 100 * MS);
        assert_eq!((rtt, backend), (100 * MS, TimingBackend::LinuxMonotonic));
    }

    #[test]
    fn receive_before_send_falls_back_to_monotonic() {
        let (rtt, backend) = select_rtt(Some(before(5 * MS)), before(5 * MS), 3 * MS);
        assert_eq!((rtt, backend), (3 * MS, TimingBackend::LinuxMonotonic));
    }

    #[test]
    fn no_kernel_timestamp_uses_monotonic() {
        let (rtt, backend) = select_rtt(None, Ok(7 * MS), 7 * MS);
        assert_eq!((rtt, backend), (7 * MS, TimingBackend::LinuxMonotonic));
    }
}
