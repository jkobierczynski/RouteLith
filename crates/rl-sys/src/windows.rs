//! Windows ICMP helper API (`IcmpSendEcho2Ex` / `Icmp6SendEcho2`).
//!
//! Needs no privileges. `ICMP_ECHO_REPLY.RoundTripTime` only has millisecond
//! resolution, so the RTT is taken with `Instant` (QPC) around the synchronous
//! call instead. The call blocks, so callers run it on a blocking thread pool.
//!
//! [`RawIcmpSocket`] is a raw ICMPv4 socket (needs Administrator). It is only
//! used as a timing reference to calibrate the helper API (design risk R1).

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

/// `IP_STATUS_BASE`: statuses at or above it are `IP_*` codes; anything below
/// is a Win32 error, i.e. the request failed on this host.
const IP_STATUS_BASE: u32 = 11000;

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

    pub(crate) fn raw(&self) -> HANDLE {
        self.handle
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
                    return no_reply(elapsed);
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
                    return no_reply(elapsed);
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

/// The call returned no reply: an `IP_*` status (time-out, unreachable, ...)
/// or a local Win32 error, which becomes `Err` so callers count it as a send failure.
fn no_reply(elapsed: Duration) -> io::Result<EchoOutcome> {
    let status = last_error();
    if status < IP_STATUS_BASE {
        #[allow(clippy::cast_possible_wrap)] // Win32 error codes fit in i32
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(from_status(status, None, elapsed, 0))
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

/// Raw ICMPv4 socket used as the timing reference for calibration. Needs
/// Administrator. Received datagrams include the IPv4 header.
#[derive(Debug)]
pub struct RawIcmpSocket {
    socket: socket2::Socket,
}

impl RawIcmpSocket {
    /// Open and bind the socket. Fails with `PermissionDenied` without Administrator.
    pub fn open() -> io::Result<Self> {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        let any = std::net::SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        socket.bind(&SockAddr::from(any))?;
        Ok(Self { socket })
    }

    /// Send one ICMP message (header and payload; the kernel adds the IP header).
    pub fn send_to(&self, packet: &[u8], dest: Ipv4Addr) -> io::Result<usize> {
        let dest = std::net::SocketAddr::from((dest, 0));
        self.socket.send_to(packet, &dest.into())
    }

    /// Receive one datagram (IPv4 header included), waiting at most `timeout`.
    /// Takes `&mut self` because it sets the socket-wide receive timeout first.
    pub fn recv(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        use std::io::Read as _;
        self.socket
            .set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        (&self.socket).read(buf)
    }
}

// ---------------------------------------------------------------------------
// Host health readings (see `crate::host`).

use crate::host::{CpuTimes, HostReading, NicCounters};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, FILETIME, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, GetIfTable2, GetIpForwardTable2,
    IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH, MIB_IF_TABLE2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_INET,
};
use windows_sys::Win32::System::Threading::GetSystemTimes;

pub(crate) fn read_host() -> HostReading {
    HostReading {
        cpu: cpu_times(),
        load1: None,
        nics: nic_counters(),
        gateways: default_gateways(),
        dns_servers: dns_servers(),
    }
}

fn filetime(f: FILETIME) -> u64 {
    (u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime)
}

fn cpu_times() -> Option<CpuTimes> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut idle, mut kernel, mut user) = (zero, zero, zero);
    // SAFETY: three valid out-pointers to local FILETIMEs.
    let ok = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) };
    if ok == 0 {
        return None;
    }
    // Kernel time includes idle time.
    let total = filetime(kernel).saturating_add(filetime(user));
    Some(CpuTimes {
        busy: total.saturating_sub(filetime(idle)),
        total,
    })
}

/// UTF-16 up to the first NUL.
fn wide(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

/// Physical interfaces only: Windows also lists filter, tunnel and other
/// virtual interfaces that would repeat the same counters.
fn nic_counters() -> Option<Vec<NicCounters>> {
    const HARDWARE_INTERFACE: u8 = 0x1;
    const FILTER_INTERFACE: u8 = 0x2;
    let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
    // SAFETY: valid out-pointer; on success the table is freed below.
    if unsafe { GetIfTable2(&mut table) } != NO_ERROR || table.is_null() {
        return None;
    }
    // SAFETY: GetIfTable2 succeeded, so `table` points to a MIB_IF_TABLE2
    // followed by `NumEntries` rows, valid until FreeMibTable.
    let rows = unsafe {
        std::slice::from_raw_parts(
            (*table).Table.as_ptr(),
            usize::try_from((*table).NumEntries).unwrap_or(0),
        )
    };
    let nics = rows
        .iter()
        .filter(|r| {
            let flags = r.InterfaceAndOperStatusFlags._bitfield;
            r.Type != IF_TYPE_SOFTWARE_LOOPBACK
                && flags & HARDWARE_INTERFACE != 0
                && flags & FILTER_INTERFACE == 0
        })
        .map(|r| NicCounters {
            name: wide(&r.Alias),
            rx_errors: r.InErrors,
            tx_errors: r.OutErrors,
            rx_drops: r.InDiscards,
            tx_drops: r.OutDiscards,
        })
        .collect();
    // SAFETY: allocated by GetIfTable2 and not used after this.
    unsafe { FreeMibTable(table.cast()) };
    Some(nics)
}

fn inet_addr(a: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: every variant starts with the address family, which says
    // which variant is valid.
    unsafe {
        match a.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
                a.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(a.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

fn default_gateways() -> Vec<IpAddr> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    // SAFETY: valid out-pointer; on success the table is freed below.
    if unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) } != NO_ERROR || table.is_null() {
        return Vec::new();
    }
    // SAFETY: as in `nic_counters`.
    let rows = unsafe {
        std::slice::from_raw_parts(
            (*table).Table.as_ptr(),
            usize::try_from((*table).NumEntries).unwrap_or(0),
        )
    };
    let mut gws: Vec<IpAddr> = rows
        .iter()
        .filter(|r| r.DestinationPrefix.PrefixLength == 0 && !r.Loopback)
        .filter_map(|r| inet_addr(&r.NextHop))
        .filter(|a| !a.is_unspecified())
        .collect();
    // SAFETY: allocated by GetIpForwardTable2 and not used after this.
    unsafe { FreeMibTable(table.cast()) };
    gws.sort_by_key(IpAddr::is_ipv6);
    gws
}

fn sockaddr(p: *const SOCKADDR) -> Option<IpAddr> {
    if p.is_null() {
        return None;
    }
    // SAFETY: the IP Helper API gives a SOCKADDR_IN or SOCKADDR_IN6 behind
    // this pointer, as its family says; read_unaligned copes with any
    // alignment.
    unsafe {
        match (*p).sa_family {
            AF_INET => {
                let a: SOCKADDR_IN = ptr::read_unaligned(p.cast());
                Some(IpAddr::V4(Ipv4Addr::from(
                    a.sin_addr.S_un.S_addr.to_ne_bytes(),
                )))
            }
            AF_INET6 => {
                let a: SOCKADDR_IN6 = ptr::read_unaligned(p.cast());
                Some(IpAddr::V6(Ipv6Addr::from(a.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

/// Windows lists `fec0:0:0:ffff::1` to `::3` on adapters that have no
/// IPv6 DNS server configured; they are placeholders, not servers.
fn placeholder_dns(a: &IpAddr) -> bool {
    match a {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[..4] == [0xfec0, 0, 0, 0xffff] && s[4..7] == [0, 0, 0] && (1..=3).contains(&s[7])
        }
        IpAddr::V4(_) => false,
    }
}

fn dns_servers() -> Vec<IpAddr> {
    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..4 {
        buf = vec![0u64; usize::try_from(size).unwrap_or(0) / 8 + 1];
        size = u32::try_from(buf.len() * 8).unwrap_or(u32::MAX);
        // SAFETY: the buffer is `size` bytes, 8-byte aligned, and outlives
        // every pointer read from it below.
        let rc = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        match rc {
            NO_ERROR => break,
            ERROR_BUFFER_OVERFLOW => {
                buf.clear();
                continue;
            }
            _ => return Vec::new(),
        }
    }
    if buf.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut adapter: *const IP_ADAPTER_ADDRESSES_LH = buf.as_ptr().cast();
    while !adapter.is_null() {
        // SAFETY: a node of the list GetAdaptersAddresses built in `buf`.
        let a = unsafe { &*adapter };
        if a.OperStatus == IfOperStatusUp && a.IfType != IF_TYPE_SOFTWARE_LOOPBACK {
            let mut dns = a.FirstDnsServerAddress;
            while !dns.is_null() {
                // SAFETY: a node of the adapter's DNS server list, in `buf`.
                let d = unsafe { &*dns };
                if let Some(ip) = sockaddr(d.Address.lpSockaddr) {
                    if !placeholder_dns(&ip) {
                        out.push(ip);
                    }
                }
                dns = d.Next;
            }
        }
        adapter = a.Next;
    }
    out
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn site_local_dns_placeholders_are_recognised() {
        assert!(placeholder_dns(&"fec0:0:0:ffff::1".parse().unwrap()));
        assert!(placeholder_dns(&"fec0:0:0:ffff::3".parse().unwrap()));
        assert!(!placeholder_dns(&"fec0:0:0:ffff::4".parse().unwrap()));
        assert!(!placeholder_dns(&"192.0.2.1".parse().unwrap()));
    }
}
