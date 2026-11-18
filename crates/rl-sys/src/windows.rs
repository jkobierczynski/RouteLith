//! Windows ICMP helper API (`IcmpSendEcho2Ex` / `Icmp6SendEcho2`).
//!
//! Needs no privileges. `ICMP_ECHO_REPLY.RoundTripTime` only has millisecond
//! resolution, so the RTT is taken with `Instant` (QPC) around the synchronous
//! call instead. The call blocks, so callers run it on a blocking thread pool.

use std::ffi::c_void;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE,
    IP_DEST_PORT_UNREACHABLE, IP_DEST_PROT_UNREACHABLE, IP_DEST_UNREACHABLE, IP_OPTION_INFORMATION,
    IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, Icmp6CreateFile, Icmp6ParseReplies,
    Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2Ex,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

/// An open ICMP (v4) or ICMPv6 handle.
#[derive(Debug)]
pub struct IcmpHandle {
    handle: HANDLE,
    v6: bool,
}

// SAFETY: ICMP handles are kernel handles, not tied to the creating thread; the
// IP Helper API documents concurrent IcmpSendEcho2* calls on one handle as supported.
unsafe impl Send for IcmpHandle {}
// SAFETY: see above; all methods take `&self` and the handle is never mutated.
unsafe impl Sync for IcmpHandle {}

/// Result of one echo request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoOutcome {
    Reply {
        from: IpAddr,
        /// QPC-timed duration of the API call.
        elapsed: Duration,
        /// The API's own millisecond RTT, kept for calibration.
        api_rtt_ms: u32,
    },
    TimedOut,
    Unreachable {
        /// Raw `IP_*` status code.
        status: u32,
    },
    TtlExpired,
    /// Any other IP status code.
    Failed {
        status: u32,
    },
}

impl IcmpHandle {
    pub fn open(v6: bool) -> io::Result<Self> {
        // SAFETY: plain constructors without arguments.
        let handle = unsafe {
            if v6 {
                Icmp6CreateFile()
            } else {
                IcmpCreateFile()
            }
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle, v6 })
    }

    pub fn is_v6(&self) -> bool {
        self.v6
    }

    /// Send one echo request and wait up to `timeout` for the reply. Blocking.
    pub fn echo(
        &self,
        dest: IpAddr,
        payload: &[u8],
        ttl: u8,
        timeout: Duration,
    ) -> io::Result<EchoOutcome> {
        let size = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload too large"))?;
        let timeout_ms = u32::try_from(timeout.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        let options = IP_OPTION_INFORMATION {
            Ttl: ttl,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: ptr::null_mut(),
        };
        // Reply header + echoed data + 8 bytes for an ICMP error + IO_STATUS_BLOCK slack.
        let mut reply =
            vec![0u64; (mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 64) / 8 + 1];
        let reply_size = u32::try_from(reply.len() * 8).unwrap_or(u32::MAX);

        match (dest, self.v6) {
            (IpAddr::V4(dst), false) => {
                let start = Instant::now();
                // SAFETY: no event and no APC, so the call is synchronous; every pointer
                // refers to a live local buffer whose size is passed alongside it.
                let n = unsafe {
                    IcmpSendEcho2Ex(
                        self.handle,
                        ptr::null_mut(),
                        None,
                        ptr::null(),
                        0,
                        u32::from_ne_bytes(dst.octets()),
                        payload.as_ptr().cast(),
                        size,
                        &options,
                        reply.as_mut_ptr().cast(),
                        reply_size,
                        timeout_ms,
                    )
                };
                let elapsed = start.elapsed();
                if n == 0 {
                    return Ok(from_status(last_error(), None, elapsed, 0));
                }
                // SAFETY: n > 0 means the buffer starts with an ICMP_ECHO_REPLY; the
                // u64-backed buffer is suitably aligned for it.
                let r: ICMP_ECHO_REPLY = unsafe { ptr::read(reply.as_ptr().cast()) };
                let from = IpAddr::V4(Ipv4Addr::from(r.Address.to_ne_bytes()));
                Ok(from_status(r.Status, Some(from), elapsed, r.RoundTripTime))
            }
            (IpAddr::V6(dst), true) => {
                let source = sockaddr_in6(Ipv6Addr::UNSPECIFIED);
                let target = sockaddr_in6(dst);
                let start = Instant::now();
                // SAFETY: as for IPv4 above.
                let n = unsafe {
                    Icmp6SendEcho2(
                        self.handle,
                        ptr::null_mut(),
                        None,
                        ptr::null(),
                        &source,
                        &target,
                        payload.as_ptr().cast(),
                        size,
                        &options,
                        reply.as_mut_ptr().cast(),
                        reply_size,
                        timeout_ms,
                    )
                };
                let elapsed = start.elapsed();
                if n == 0 {
                    return Ok(from_status(last_error(), None, elapsed, 0));
                }
                // SAFETY: the buffer holds the reply written by Icmp6SendEcho2.
                let parsed =
                    unsafe { Icmp6ParseReplies(reply.as_mut_ptr().cast::<c_void>(), reply_size) };
                if parsed == 0 {
                    return Ok(from_status(last_error(), None, elapsed, 0));
                }
                // SAFETY: a parsed reply buffer starts with ICMPV6_ECHO_REPLY; aligned as above.
                let r: ICMPV6_ECHO_REPLY_LH = unsafe { ptr::read(reply.as_ptr().cast()) };
                let mut octets = [0u8; 16];
                let words = r.Address.sin6_addr; // copy out of the packed struct
                for (i, word) in words.iter().enumerate() {
                    octets[i * 2..i * 2 + 2].copy_from_slice(&word.to_ne_bytes());
                }
                let from = IpAddr::V6(Ipv6Addr::from(octets));
                let (status, api_rtt_ms) = (r.Status, r.RoundTripTime);
                Ok(from_status(status, Some(from), elapsed, api_rtt_ms))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "address family does not match the ICMP handle",
            )),
        }
    }
}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from Icmp(6)CreateFile and is closed exactly once.
        unsafe {
            IcmpCloseHandle(self.handle);
        }
    }
}

fn last_error() -> u32 {
    // SAFETY: reads the calling thread's last-error value.
    unsafe { GetLastError() }
}

fn from_status(
    status: u32,
    from: Option<IpAddr>,
    elapsed: Duration,
    api_rtt_ms: u32,
) -> EchoOutcome {
    match (status, from) {
        (IP_SUCCESS, Some(from)) => EchoOutcome::Reply {
            from,
            elapsed,
            api_rtt_ms,
        },
        (IP_REQ_TIMED_OUT, _) => EchoOutcome::TimedOut,
        (IP_TTL_EXPIRED_TRANSIT, _) => EchoOutcome::TtlExpired,
        (
            IP_DEST_NET_UNREACHABLE
            | IP_DEST_HOST_UNREACHABLE
            | IP_DEST_PROT_UNREACHABLE
            | IP_DEST_PORT_UNREACHABLE
            | IP_DEST_UNREACHABLE,
            _,
        ) => EchoOutcome::Unreachable { status },
        (status, _) => EchoOutcome::Failed { status },
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
