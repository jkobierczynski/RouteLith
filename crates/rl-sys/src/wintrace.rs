//! Asynchronous ICMP echo for the tracer (architecture doc §21.9 P3).
//!
//! A trace has many probes in flight, and probes to silent hops wait for the
//! whole timeout, so blocking calls on a thread pool would tie up hundreds of
//! threads. Instead one dedicated thread issues every request with
//! `IcmpSendEcho2Ex` / `Icmp6SendEcho2` and an APC routine, and sleeps
//! alertably in between: requests reach it as user APCs (`QueueUserAPC`), and
//! replies come back as APCs on the same thread. The RTT is QPC (`Instant`)
//! from just before the call to the start of the reply routine.
//!
//! Needs no privileges.

use std::ffi::c_void;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_IO_PENDING, GetLastError};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE,
    IP_DEST_PORT_UNREACHABLE, IP_DEST_PROT_UNREACHABLE, IP_DEST_UNREACHABLE, IP_OPTION_INFORMATION,
    IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, Icmp6ParseReplies, Icmp6SendEcho2,
    IcmpParseReplies, IcmpSendEcho2Ex,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Threading::{INFINITE, QueueUserAPC, SleepEx};

use crate::windows::IcmpHandle;

/// `IP_STATUS_BASE`: statuses below it are Win32 errors on this host.
const IP_STATUS_BASE: u32 = 11000;

/// What came back for one trace probe.
#[derive(Debug)]
pub enum TraceOutcome {
    /// Echo reply from the destination.
    Reply {
        from: IpAddr,
        elapsed: Duration,
    },
    /// Time Exceeded from a router on the path.
    TtlExpired {
        from: IpAddr,
        elapsed: Duration,
    },
    /// Destination Unreachable; `status` is the raw `IP_DEST_*` code.
    Unreachable {
        from: Option<IpAddr>,
        status: u32,
        elapsed: Duration,
    },
    TimedOut,
    /// Any other `IP_*` status.
    Failed {
        status: u32,
    },
    /// The request could not be issued on this host.
    SendError(io::Error),
}

/// Called once with the outcome, on the worker thread: keep it short.
pub type Done = Box<dyn FnOnce(TraceOutcome) + Send>;

/// One probe to send.
#[allow(missing_debug_implementations)] // `done` is a closure
pub struct TraceRequest {
    pub dest: IpAddr,
    pub ttl: u8,
    pub payload: Arc<[u8]>,
    pub timeout: Duration,
    pub done: Done,
}

/// The thread that issues trace probes. Dropping it stops the thread once
/// the requests in flight have completed.
pub struct TraceWorker {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

struct Shared {
    v4: Option<IcmpHandle>,
    v6: Option<IcmpHandle>,
    stop: AtomicBool,
}

impl std::fmt::Debug for TraceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceWorker")
            .field("v4", &self.shared.v4.is_some())
            .field("v6", &self.shared.v6.is_some())
            .finish()
    }
}

/// A request on its way through the worker. Lives on the heap from
/// `submit` until the reply routine (or a failed issue) frees it; every
/// buffer the API writes to or reads from is in here.
struct InFlight {
    shared: Arc<Shared>,
    dest: IpAddr,
    payload: Arc<[u8]>,
    options: IP_OPTION_INFORMATION,
    source6: SOCKADDR_IN6,
    target6: SOCKADDR_IN6,
    timeout_ms: u32,
    /// u64-backed so the reply structures read from it are aligned.
    reply: Vec<u64>,
    start: Option<Instant>,
    done: Option<Done>,
}

impl InFlight {
    fn reply_size(&self) -> u32 {
        u32::try_from(self.reply.len() * 8).unwrap_or(u32::MAX)
    }

    fn finish(mut self, outcome: TraceOutcome) {
        if let Some(done) = self.done.take() {
            done(outcome);
        }
    }
}

impl TraceWorker {
    /// Open the ICMP handles and start the thread. A family whose handle
    /// cannot be opened (no IPv6 stack, say) fails its requests instead.
    pub fn start() -> io::Result<Self> {
        let v4 = IcmpHandle::open(false);
        let v6 = IcmpHandle::open(true).ok();
        let v4 = match (v4, &v6) {
            (Ok(h), _) => Some(h),
            (Err(_), Some(_)) => None,
            (Err(e), None) => return Err(e),
        };
        let shared = Arc::new(Shared {
            v4,
            v6,
            stop: AtomicBool::new(false),
        });
        let thread = std::thread::Builder::new()
            .name("rl-trace-icmp".into())
            .spawn({
                let shared = Arc::clone(&shared);
                move || {
                    while !shared.stop.load(Ordering::Acquire) {
                        // SAFETY: plain alertable sleep; APCs queued to this
                        // thread run inside it.
                        unsafe {
                            SleepEx(INFINITE, 1);
                        }
                    }
                    // Let requests in flight complete so their buffers are
                    // not freed while the API may still write to them.
                    while Arc::strong_count(&shared) > 2 {
                        // SAFETY: as above, with a bound so the loop re-checks.
                        unsafe {
                            SleepEx(50, 1);
                        }
                    }
                }
            })?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    /// Whether requests to this family can be sent.
    pub fn supports(&self, v6: bool) -> bool {
        if v6 {
            self.shared.v6.is_some()
        } else {
            self.shared.v4.is_some()
        }
    }

    /// Queue one probe. `req.done` is called exactly once, on the worker.
    pub fn submit(&self, req: TraceRequest) {
        let v6 = req.dest.is_ipv6();
        let (source6, target6) = match req.dest {
            IpAddr::V6(d) => (sockaddr_in6(Ipv6Addr::UNSPECIFIED), sockaddr_in6(d)),
            IpAddr::V4(_) => (
                sockaddr_in6(Ipv6Addr::UNSPECIFIED),
                sockaddr_in6(Ipv6Addr::UNSPECIFIED),
            ),
        };
        let words = (mem::size_of::<ICMPV6_ECHO_REPLY_LH>().max(mem::size_of::<ICMP_ECHO_REPLY>())
            + req.payload.len()
            + 8
            + mem::size_of::<IO_STATUS_BLOCK>()
            + 64)
            / 8
            + 1;
        let flight = Box::new(InFlight {
            shared: Arc::clone(&self.shared),
            dest: req.dest,
            payload: req.payload,
            options: IP_OPTION_INFORMATION {
                Ttl: req.ttl,
                Tos: 0,
                Flags: 0,
                OptionsSize: 0,
                OptionsData: ptr::null_mut(),
            },
            source6,
            target6,
            timeout_ms: u32::try_from(req.timeout.as_millis())
                .unwrap_or(u32::MAX)
                .max(1),
            reply: vec![0u64; words],
            start: None,
            done: Some(req.done),
        });
        if !self.supports(v6) {
            let family = if v6 { "IPv6" } else { "IPv4" };
            flight.finish(TraceOutcome::SendError(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("no ICMP handle for {family}"),
            )));
            return;
        }
        let Some(thread) = &self.thread else {
            flight.finish(TraceOutcome::SendError(io::Error::other("worker stopped")));
            return;
        };
        let raw = Box::into_raw(flight);
        // SAFETY: the thread handle stays valid while its JoinHandle lives
        // (it is joined only in Drop); `raw` is a leaked Box that `issue`
        // takes back exactly once.
        let queued = unsafe { QueueUserAPC(Some(issue), thread.as_raw_handle(), raw as usize) };
        if queued == 0 {
            let err = io::Error::last_os_error();
            // SAFETY: the APC was not queued, so ownership is still ours.
            let flight = unsafe { Box::from_raw(raw) };
            flight.finish(TraceOutcome::SendError(err));
        }
    }
}

impl Drop for TraceWorker {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // SAFETY: wakes the sleeping thread so it sees `stop`; the handle
            // is valid until the join below.
            unsafe {
                QueueUserAPC(Some(wake), thread.as_raw_handle(), 0);
            }
            let _ = thread.join();
        }
    }
}

unsafe extern "system" fn wake(_: usize) {}

/// Runs on the worker: issue the request with the reply APC.
unsafe extern "system" fn issue(param: usize) {
    // SAFETY: `param` is the Box leaked by `submit`, handed over once.
    let mut flight = unsafe { Box::from_raw(param as *mut InFlight) };
    let size = u16::try_from(flight.payload.len()).unwrap_or(u16::MAX);
    let reply_size = flight.reply_size();
    let shared = Arc::clone(&flight.shared);
    flight.start = Some(Instant::now());
    let raw = Box::into_raw(flight);
    // SAFETY: `raw` stays allocated until `on_reply` (or the failure path
    // below) frees it, so every pointer into it handed to the API outlives
    // the request; the handle lives in `shared`, which `raw` keeps alive.
    let n = unsafe {
        let f = &mut *raw;
        match (f.dest, &shared.v4, &shared.v6) {
            (IpAddr::V4(dst), Some(h), _) => IcmpSendEcho2Ex(
                h.raw(),
                ptr::null_mut(),
                Some(on_reply),
                raw as *const c_void,
                0,
                u32::from_ne_bytes(dst.octets()),
                f.payload.as_ptr().cast(),
                size,
                &f.options,
                f.reply.as_mut_ptr().cast(),
                reply_size,
                f.timeout_ms,
            ),
            (IpAddr::V6(_), _, Some(h)) => Icmp6SendEcho2(
                h.raw(),
                ptr::null_mut(),
                Some(on_reply),
                raw as *const c_void,
                &f.source6,
                &f.target6,
                f.payload.as_ptr().cast(),
                size,
                &f.options,
                f.reply.as_mut_ptr().cast(),
                reply_size,
                f.timeout_ms,
            ),
            _ => 0,
        }
    };
    // SAFETY: reads this thread's last-error value.
    let err = unsafe { GetLastError() };
    if n == 0 && err == ERROR_IO_PENDING {
        return; // `on_reply` takes it from here.
    }
    // Completed or failed without queuing the APC: finish here.
    // SAFETY: no APC was queued for `raw`, so we still own it.
    let flight = unsafe { Box::from_raw(raw) };
    if n == 0 {
        let outcome = if err < IP_STATUS_BASE {
            #[allow(clippy::cast_possible_wrap)] // Win32 error codes fit in i32
            TraceOutcome::SendError(io::Error::from_raw_os_error(err as i32))
        } else {
            map_status(err, None, Duration::ZERO)
        };
        flight.finish(outcome);
    } else {
        let elapsed = flight.start.map_or(Duration::ZERO, |s| s.elapsed());
        let outcome = parse(&flight, elapsed);
        flight.finish(outcome);
    }
}

/// Runs on the worker when the reply (or the timeout) arrives.
unsafe extern "system" fn on_reply(ctx: *mut c_void, _iosb: *mut IO_STATUS_BLOCK, _reserved: u32) {
    let end = Instant::now();
    // SAFETY: `ctx` is the pointer `issue` passed as the APC context, freed
    // only here.
    let mut flight = unsafe { Box::from_raw(ctx.cast::<InFlight>()) };
    let elapsed = flight.start.map_or(Duration::ZERO, |s| end - s);
    let size = flight.reply_size();
    // SAFETY: the buffer is the one the API wrote to; parsing it in place
    // is what the API requires for an asynchronous reply.
    let n = unsafe {
        let buf = flight.reply.as_mut_ptr().cast::<c_void>();
        if flight.dest.is_ipv6() {
            Icmp6ParseReplies(buf, size)
        } else {
            IcmpParseReplies(buf, size)
        }
    };
    let outcome = if n == 0 {
        // SAFETY: reads this thread's last-error value.
        let err = unsafe { GetLastError() };
        // The reply structure can still name a responder for an error.
        match read_reply(&flight) {
            Some((status, from)) if status != IP_SUCCESS && status >= IP_STATUS_BASE => {
                map_status(status, from, elapsed)
            }
            _ => map_status(err, None, elapsed),
        }
    } else {
        parse(&flight, elapsed)
    };
    flight.finish(outcome);
}

fn parse(flight: &InFlight, elapsed: Duration) -> TraceOutcome {
    match read_reply(flight) {
        Some((status, from)) => map_status(status, from, elapsed),
        None => TraceOutcome::Failed { status: 0 },
    }
}

/// Status and responder of the first reply in the buffer.
fn read_reply(flight: &InFlight) -> Option<(u32, Option<IpAddr>)> {
    if flight.dest.is_ipv6() {
        // SAFETY: the buffer is at least as large as the structure, aligned
        // (u64-backed) and initialised (zeroed, then written by the API).
        let r: ICMPV6_ECHO_REPLY_LH = unsafe { ptr::read(flight.reply.as_ptr().cast()) };
        let words = r.Address.sin6_addr;
        let mut octets = [0u8; 16];
        for (i, word) in words.iter().enumerate() {
            octets[i * 2..i * 2 + 2].copy_from_slice(&word.to_ne_bytes());
        }
        let addr = Ipv6Addr::from(octets);
        Some((
            r.Status,
            (!addr.is_unspecified()).then_some(IpAddr::V6(addr)),
        ))
    } else {
        // SAFETY: as above, for ICMP_ECHO_REPLY.
        let r: ICMP_ECHO_REPLY = unsafe { ptr::read(flight.reply.as_ptr().cast()) };
        let addr = Ipv4Addr::from(r.Address.to_ne_bytes());
        Some((
            r.Status,
            (!addr.is_unspecified()).then_some(IpAddr::V4(addr)),
        ))
    }
}

fn map_status(status: u32, from: Option<IpAddr>, elapsed: Duration) -> TraceOutcome {
    match (status, from) {
        (IP_SUCCESS, Some(from)) => TraceOutcome::Reply { from, elapsed },
        (IP_TTL_EXPIRED_TRANSIT, Some(from)) => TraceOutcome::TtlExpired { from, elapsed },
        (IP_REQ_TIMED_OUT, _) => TraceOutcome::TimedOut,
        (
            IP_DEST_NET_UNREACHABLE
            | IP_DEST_HOST_UNREACHABLE
            | IP_DEST_PROT_UNREACHABLE
            | IP_DEST_PORT_UNREACHABLE
            | IP_DEST_UNREACHABLE,
            from,
        ) => TraceOutcome::Unreachable {
            from,
            status,
            elapsed,
        },
        (status, _) => TraceOutcome::Failed { status },
    }
}

fn sockaddr_in6(addr: Ipv6Addr) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: addr.octets(),
            },
        },
        ..Default::default()
    }
}
