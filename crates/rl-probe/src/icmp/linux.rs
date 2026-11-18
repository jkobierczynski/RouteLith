//! Linux engine: one shared ping socket per family, a reader task that
//! demultiplexes replies by sequence number, and kernel receive timestamps.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

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
    user: Instant,
}

impl Engine {
    pub(super) fn open(v6: bool, payload_size: usize) -> Result<Self, ProbeError> {
        let sock = PingSocket::open(v6).map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => ProbeError::PingSocketNotPermitted,
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

    pub(super) async fn sample(&self, dest: IpAddr, timeout: Duration) -> (Sample, TimingBackend) {
        let nonce = self
            .nonce_seed
            .hash_one(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = oneshot::channel();
        let Some(seq) = self.register(Pending {
            nonce,
            dest,
            reply: tx,
        }) else {
            let err = SampleError::Other("too many requests in flight".into());
            return (Sample::Error(err), TimingBackend::LinuxMonotonic);
        };
        let v6 = self.shared.sock.get_ref().is_v6();
        let packet = build_echo_request(v6, 0, seq, nonce, self.payload_size);

        let sent = self.send(&packet, dest).await;
        let (tx_wall, tx_user) = match sent {
            Ok(times) => times,
            Err(e) => {
                self.unregister(seq);
                return (
                    Sample::Error(SampleError::Other(e.to_string())),
                    self.preferred_backend(),
                );
            }
        };

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(rx)) => {
                let user_rtt = rx.user.saturating_duration_since(tx_user);
                let kernel_rtt = rx
                    .kernel
                    .and_then(|k| k.duration_since(tx_wall).ok())
                    .filter(|k| *k <= user_rtt + KERNEL_TS_SLACK);
                match kernel_rtt {
                    Some(rtt) => (ok_sample(rtt), TimingBackend::LinuxKernelTimestamp),
                    None => (ok_sample(user_rtt), TimingBackend::LinuxMonotonic),
                }
            }
            _ => {
                self.unregister(seq);
                (Sample::Lost, self.preferred_backend())
            }
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

    fn unregister(&self, seq: u16) {
        self.shared
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&seq);
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.reader.abort();
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
                    let user = Instant::now();
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
