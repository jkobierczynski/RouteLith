//! Linux tracer: one ping socket per trace (§21.9 P2).
//!
//! The TTL is set just before each send, under a lock, so concurrent probes
//! of one trace never send with each other's TTL. With `IP_RECVERR` the
//! kernel queues Time Exceeded and Unreachable for our own echo requests on
//! the socket's error queue, with the responder address and a kernel time
//! stamp; the quoted request carries our sequence number. Echo replies from
//! the destination arrive on the normal queue, as for the ICMP probe.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::io::{self, ErrorKind};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use rl_core::TimingBackend;
use rl_probe::ProbeError;
use rl_probe::icmp::select_rtt;
use rl_probe::packet::{build_echo_request, parse_echo_reply};
use rl_sys::linux::{IcmpErrorKind, PingSocket};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use tokio::task::AbortHandle;

use crate::{BoxFuture, Outcome, PAYLOAD_SIZE, ProbeResult, Tracer, payload_fill};

const ECHO_REQUEST_V4: u8 = 8;
const ECHO_REQUEST_V6: u8 = 128;
/// Extra tries of a send that failed with an ICMP-derived socket error.
const SEND_ATTEMPTS: u32 = 3;

/// Errors the kernel derives from received ICMP errors (`icmp_err_convert`
/// and its IPv6 counterpart), which a pending socket error can carry.
/// Pending socket errors read through in one drain before the reader
/// backs off.
const MAX_SOCKET_ERRORS: u32 = 64;

fn is_icmp_errno(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::EHOSTUNREACH
                | libc::ENETUNREACH
                | libc::ECONNREFUSED
                | libc::EPROTO
                | libc::EMSGSIZE
                | libc::EACCES
                | libc::ENONET
                | libc::EOPNOTSUPP
                | libc::ENOPROTOOPT
                | libc::EHOSTDOWN
                | libc::ENETDOWN
                | libc::EREMOTEIO
        )
    )
}

#[derive(Debug)]
pub(crate) struct LinuxTracer {
    dest: IpAddr,
    shared: Arc<Shared>,
    reader: AbortHandle,
    next_seq: AtomicU16,
    nonce_counter: AtomicU64,
    nonce_seed: RandomState,
}

#[derive(Debug)]
struct Shared {
    sock: AsyncFd<PingSocket>,
    /// Held across set-TTL-and-send.
    send_lock: Mutex<()>,
    pending: Mutex<HashMap<u16, Pending>>,
}

#[derive(Debug)]
struct Pending {
    nonce: u64,
    reply: oneshot::Sender<Rx>,
}

#[derive(Debug)]
enum Answer {
    Reply(IpAddr),
    Error {
        kind: IcmpErrorKind,
        code: u8,
        from: Option<IpAddr>,
    },
}

#[derive(Debug)]
struct Rx {
    answer: Answer,
    kernel: Option<SystemTime>,
    wall: SystemTime,
    user: Instant,
}

/// Removes the pending entry when a probe ends for any reason.
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

impl LinuxTracer {
    pub(crate) fn open(dest: IpAddr) -> Result<Self, crate::TraceError> {
        let sock = PingSocket::open(dest.is_ipv6()).map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => ProbeError::PingSocketNotPermitted(e),
            _ => ProbeError::Io(e),
        })?;
        sock.enable_recverr()?;
        let shared = Arc::new(Shared {
            sock: sock.into_async()?,
            send_lock: Mutex::new(()),
            pending: Mutex::new(HashMap::new()),
        });
        let reader = tokio::spawn(read_loop(Arc::clone(&shared), dest)).abort_handle();
        Ok(Self {
            dest,
            shared,
            reader,
            next_seq: AtomicU16::new(0),
            nonce_counter: AtomicU64::new(0),
            nonce_seed: RandomState::new(),
        })
    }

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

    /// Set the TTL and send, recording the clocks just before `sendto`.
    ///
    /// With `IP_RECVERR`, each ICMP error the socket receives (every Time
    /// Exceeded) is also left as a pending socket error, and the next
    /// `sendto` fails with it once (`EHOSTUNREACH`, say) while clearing it.
    /// That error is about an earlier probe, not this one, so the send is
    /// tried again; only an error that comes back every time is real.
    async fn send(&self, packet: &[u8], ttl: u8) -> io::Result<(SystemTime, Instant)> {
        let mut attempts = 0;
        loop {
            let mut guard = self.shared.sock.writable().await?;
            let mut times = None;
            let result = guard.try_io(|s| {
                let _lock = self
                    .shared
                    .send_lock
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                s.get_ref().set_ttl(u32::from(ttl))?;
                times = Some((SystemTime::now(), Instant::now()));
                s.get_ref().send_to(packet, self.dest)
            });
            match result {
                Ok(Ok(_)) => {
                    return times.ok_or_else(|| io::Error::other("send time not recorded"));
                }
                Ok(Err(e)) if attempts < SEND_ATTEMPTS && is_icmp_errno(&e) => attempts += 1,
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }

    fn preferred(&self) -> TimingBackend {
        if self.shared.sock.get_ref().has_kernel_timestamps() {
            TimingBackend::LinuxKernelTimestamp
        } else {
            TimingBackend::LinuxMonotonic
        }
    }

    async fn probe_inner(&self, ttl: u8, timeout: Duration) -> ProbeResult {
        let nonce = self
            .nonce_seed
            .hash_one(self.nonce_counter.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = oneshot::channel();
        let Some(seq) = self.register(Pending { nonce, reply: tx }) else {
            return self.failed("too many probes in flight".into());
        };
        let _guard = PendingGuard {
            shared: &self.shared,
            seq,
            nonce,
        };
        let mut packet = build_echo_request(self.dest.is_ipv6(), 0, seq, nonce, PAYLOAD_SIZE);
        payload_fill(&mut packet[16..]);
        if !self.dest.is_ipv6() {
            // The kernel fills in the v4 checksum on ping sockets, but keep
            // the packet valid as built.
            packet[2..4].copy_from_slice(&[0, 0]);
            let sum = rl_probe::packet::checksum(&packet);
            packet[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        let (tx_wall, tx_user) = match self.send(&packet, ttl).await {
            Ok(t) => t,
            Err(e) => return self.failed(e.to_string()),
        };
        let Ok(Ok(rx)) = tokio::time::timeout(timeout, rx).await else {
            return ProbeResult {
                outcome: Outcome::Lost,
                timing: self.preferred(),
            };
        };
        let (rtt, timing) = select_rtt(
            rx.kernel.map(|k| k.duration_since(tx_wall)),
            rx.wall.duration_since(tx_wall),
            rx.user.saturating_duration_since(tx_user),
        );
        let outcome = match rx.answer {
            Answer::Reply(from) => Outcome::Reply { from, rtt },
            Answer::Error {
                kind: IcmpErrorKind::TimeExceeded,
                from: Some(from),
                ..
            } => Outcome::TimeExceeded { from, rtt },
            Answer::Error {
                kind: IcmpErrorKind::Unreachable,
                from,
                code,
            } => Outcome::Unreachable { from, code, rtt },
            // A local error or Time Exceeded without an address.
            Answer::Error { .. } => Outcome::Lost,
        };
        ProbeResult { outcome, timing }
    }

    fn failed(&self, why: String) -> ProbeResult {
        ProbeResult {
            outcome: Outcome::SendFailed(why),
            timing: self.preferred(),
        }
    }
}

impl Drop for LinuxTracer {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Tracer for LinuxTracer {
    fn dest(&self) -> IpAddr {
        self.dest
    }

    fn timing(&self) -> TimingBackend {
        self.preferred()
    }

    fn probe(&self, ttl: u8, timeout: Duration) -> BoxFuture<'_, ProbeResult> {
        Box::pin(self.probe_inner(ttl, timeout))
    }
}

/// Hand an answer to the probe waiting for `seq`, if the nonce matches (when
/// the answer quotes one: routers may quote only 8 bytes of our request).
fn deliver(shared: &Shared, seq: u16, nonce: Option<u64>, rx: Rx) {
    let mut pending = shared
        .pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let matches = pending
        .get(&seq)
        .is_some_and(|p| nonce.is_none_or(|n| n == p.nonce));
    if let Some(p) = matches.then(|| pending.remove(&seq)).flatten() {
        let _ = p.reply.send(rx);
    }
}

/// The sequence number and nonce of the echo request an ICMP error quotes.
fn quoted_request(v6: bool, buf: &[u8]) -> Option<(u16, Option<u64>)> {
    let request = if v6 { ECHO_REQUEST_V6 } else { ECHO_REQUEST_V4 };
    if buf.len() < 8 || buf[0] != request {
        return None;
    }
    let seq = u16::from_be_bytes([buf[6], buf[7]]);
    let nonce = buf
        .get(8..16)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes);
    Some((seq, nonce))
}

async fn read_loop(shared: Arc<Shared>, dest: IpAddr) {
    let v6 = dest.is_ipv6();
    let mut buf = vec![0u8; 65_536];
    loop {
        let Ok(mut guard) = shared
            .sock
            .ready(Interest::READABLE | Interest::ERROR)
            .await
        else {
            return;
        };
        // A read that keeps failing (a security policy that refuses
        // MSG_ERRQUEUE, say) must not spin here: back off and try again.
        let mut stalled = false;
        // Error queue first: Time Exceeded and Unreachable.
        loop {
            match shared.sock.get_ref().recv_err(&mut buf) {
                Ok(err) => {
                    let (wall, user) = (SystemTime::now(), Instant::now());
                    let Some((seq, nonce)) = quoted_request(v6, &buf[..err.len]) else {
                        continue;
                    };
                    // Redirects, Source Quench, local errors: the probe may
                    // still be answered, so leave it waiting.
                    let useful = match err.kind {
                        IcmpErrorKind::TimeExceeded => err.offender.is_some(),
                        IcmpErrorKind::Unreachable => true,
                        IcmpErrorKind::Other => false,
                    };
                    if !useful {
                        continue;
                    }
                    let rx = Rx {
                        answer: Answer::Error {
                            kind: err.kind,
                            code: err.icmp_code,
                            from: err.offender,
                        },
                        kernel: err.kernel_time,
                        wall,
                        user,
                    };
                    deliver(&shared, seq, nonce, rx);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                // A malformed message (already read): skip it.
                Err(e) if e.raw_os_error().is_none() => continue,
                Err(_) => {
                    stalled = true;
                    break;
                }
            }
        }
        // Then echo replies.
        let mut socket_errors = 0;
        loop {
            match shared.sock.get_ref().recv(&mut buf) {
                Ok(received) => {
                    socket_errors = 0;
                    let (wall, user) = (SystemTime::now(), Instant::now());
                    let Some(reply) = parse_echo_reply(v6, &buf[..received.len]) else {
                        continue;
                    };
                    let from = received.from.unwrap_or(dest);
                    if from != dest || reply.nonce.is_none() {
                        continue;
                    }
                    let rx = Rx {
                        answer: Answer::Reply(from),
                        kernel: received.kernel_time,
                        wall,
                        user,
                    };
                    deliver(&shared, reply.seq, reply.nonce, rx);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                // With IP_RECVERR a queued ICMP error also surfaces once as
                // an error here (EHOSTUNREACH and the like), and reading it
                // clears it; the error queue has the details.
                // Each queued error clears one; a socket that keeps
                // failing (a security policy, say) counts as stalled.
                Err(e) if is_icmp_errno(&e) && socket_errors < MAX_SOCKET_ERRORS => {
                    socket_errors += 1;
                }
                Err(_) => {
                    stalled = true;
                    break;
                }
            }
        }
        if stalled {
            drop(guard);
            tokio::time::sleep(Duration::from_millis(10)).await;
        } else {
            guard.clear_ready();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_request_with_and_without_nonce() {
        let mut pkt = build_echo_request(false, 0, 513, 77, PAYLOAD_SIZE);
        assert_eq!(quoted_request(false, &pkt), Some((513, Some(77))));
        assert_eq!(quoted_request(false, &pkt[..8]), Some((513, None)));
        assert_eq!(
            quoted_request(true, &pkt),
            None,
            "v4 request on a v6 socket"
        );
        pkt[0] = 0; // an echo reply is not a request
        assert_eq!(quoted_request(false, &pkt), None);
    }
}
