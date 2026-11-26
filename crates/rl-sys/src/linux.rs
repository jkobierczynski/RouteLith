//! Linux unprivileged ICMP "ping sockets" (`SOCK_DGRAM` + `IPPROTO_ICMP[V6]`).
//!
//! Needs the process GID inside `net.ipv4.ping_group_range` (that sysctl also
//! governs ICMPv6 ping sockets). The kernel rewrites the ICMP identifier to the
//! socket's local "port" and only delivers echo replies for that identifier, so
//! replies are matched on sequence number (plus a payload nonce, in `rl-probe`).

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::ptr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;

/// A non-blocking ICMP ping socket for one address family.
#[derive(Debug)]
pub struct PingSocket {
    inner: Socket,
    v6: bool,
    kernel_timestamps: bool,
}

/// One datagram read from a [`PingSocket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    /// Bytes written to the buffer: the ICMP message, starting at its header.
    pub len: usize,
    /// Source address of the reply.
    pub from: Option<IpAddr>,
    /// Kernel receive timestamp (`SO_TIMESTAMPNS`, `CLOCK_REALTIME`), if enabled.
    pub kernel_time: Option<SystemTime>,
}

/// What an ICMP error on the error queue says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpErrorKind {
    /// Time Exceeded in transit: a router on the path answered.
    TimeExceeded,
    /// Destination Unreachable (any code).
    Unreachable,
    /// Any other ICMP error, or a local one (`SO_EE_ORIGIN_LOCAL`).
    Other,
}

/// One message read from the error queue of a [`PingSocket`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpError {
    /// Bytes of the original packet written to the buffer, from its ICMP header.
    pub len: usize,
    pub kind: IcmpErrorKind,
    pub icmp_type: u8,
    pub icmp_code: u8,
    /// The host that sent the ICMP error (the router or the destination).
    pub offender: Option<IpAddr>,
    /// Kernel receive timestamp of the ICMP error, if enabled.
    pub kernel_time: Option<SystemTime>,
}

impl PingSocket {
    /// Open a ping socket. `PermissionDenied` means the caller's group is not in
    /// `net.ipv4.ping_group_range`.
    pub fn open(v6: bool) -> io::Result<Self> {
        let (domain, protocol) = if v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let inner = Socket::new(domain, Type::DGRAM, Some(protocol))?;
        inner.set_nonblocking(true)?;
        inner.set_cloexec(true)?;
        let kernel_timestamps = enable_timestamps(&inner).is_ok();
        Ok(Self {
            inner,
            v6,
            kernel_timestamps,
        })
    }

    /// Register the socket with the Tokio reactor. Must be called inside a runtime.
    pub fn into_async(self) -> io::Result<AsyncFd<PingSocket>> {
        // SAFETY: `PingSocket` owns its socket, so the descriptor stays open and
        // unchanged until the AsyncFd (which takes ownership) is dropped, and
        // `as_raw_fd` always returns that same descriptor.
        unsafe { AsyncFd::register(self) }.map_err(io::Error::from)
    }

    pub fn is_v6(&self) -> bool {
        self.v6
    }

    /// Whether the kernel attaches receive timestamps to each datagram.
    pub fn has_kernel_timestamps(&self) -> bool {
        self.kernel_timestamps
    }

    /// Send one ICMP message (header included) to `dest`. Non-blocking.
    pub fn send_to(&self, packet: &[u8], dest: IpAddr) -> io::Result<usize> {
        self.inner
            .send_to(packet, &SockAddr::from(SocketAddr::new(dest, 0)))
    }

    /// Set the TTL / hop limit of outgoing packets.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        if self.v6 {
            self.inner.set_unicast_hops_v6(ttl)
        } else {
            self.inner.set_ttl_v4(ttl)
        }
    }

    /// Queue ICMP errors about this socket's own packets (Time Exceeded,
    /// Destination Unreachable) on the error queue, read with
    /// [`recv_err`](Self::recv_err). Used by the tracer.
    pub fn enable_recverr(&self) -> io::Result<()> {
        let (level, name) = if self.v6 {
            (libc::SOL_IPV6, libc::IPV6_RECVERR)
        } else {
            (libc::SOL_IP, libc::IP_RECVERR)
        };
        let on: libc::c_int = 1;
        // SAFETY: `on` is a live c_int and its exact size is passed as the option length.
        let rc = unsafe {
            libc::setsockopt(
                self.inner.as_raw_fd(),
                level,
                name,
                ptr::from_ref(&on).cast(),
                mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Read one ICMP error from the error queue. Non-blocking: returns
    /// `WouldBlock` when the queue is empty. The buffer receives the start of
    /// the packet the error is about (our echo request, from its ICMP header).
    pub fn recv_err(&self, buf: &mut [u8]) -> io::Result<IcmpError> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut addr = MaybeUninit::<libc::sockaddr_storage>::zeroed();
        // Room for the timestamp and sock_extended_err + offender sockaddr_in6.
        let mut control = [0u64; 32];
        // SAFETY: an all-zero `msghdr` is valid; the fields used are set below.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = addr.as_mut_ptr().cast();
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control) as _;

        // SAFETY: as in `recv`: every pointer refers to a live local buffer
        // whose length is given alongside it.
        let n = unsafe {
            libc::recvmsg(
                self.inner.as_raw_fd(),
                &mut msg,
                libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = usize::try_from(n).map_err(|_| io::Error::other("negative length"))?;
        let kernel_time = timestamp_from_control(&msg);
        let ext = extended_err_from_control(&msg, self.v6)
            .ok_or_else(|| io::Error::other("error queue message without sock_extended_err"))?;
        Ok(IcmpError {
            len,
            kind: ext.0,
            icmp_type: ext.1,
            icmp_code: ext.2,
            offender: ext.3,
            kernel_time,
        })
    }

    /// Read one datagram. Non-blocking: returns `WouldBlock` when nothing is queued.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Received> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut addr = MaybeUninit::<libc::sockaddr_storage>::zeroed();
        // u64 elements keep the control buffer aligned for `cmsghdr`.
        let mut control = [0u64; 16];

        // SAFETY: an all-zero `msghdr` is a valid value (null pointers, zero lengths);
        // the fields that matter are set right below.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name = addr.as_mut_ptr().cast();
        msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of_val(&control) as _;

        // SAFETY: every pointer in `msg` refers to a live local buffer whose length
        // is given alongside it, and all of them outlive the call.
        let n = unsafe { libc::recvmsg(self.inner.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let len = usize::try_from(n).map_err(|_| io::Error::other("negative length"))?;

        // SAFETY: recvmsg filled at most `msg_namelen` bytes of the zero-initialised
        // `sockaddr_storage`, so it is fully initialised.
        let from = unsafe { sockaddr_to_ip(addr.assume_init_ref()) };
        let kernel_time = timestamp_from_control(&msg);
        Ok(Received {
            len,
            from,
            kernel_time,
        })
    }
}

impl AsRawFd for PingSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsFd for PingSocket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

fn enable_timestamps(sock: &Socket) -> io::Result<()> {
    let on: libc::c_int = 1;
    // SAFETY: `on` is a live c_int and its exact size is passed as the option length.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPNS,
            ptr::from_ref(&on).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn timestamp_from_control(msg: &libc::msghdr) -> Option<SystemTime> {
    // SAFETY: `msg` was filled by a successful recvmsg, so its control pointer and
    // `msg_controllen` describe valid cmsg headers inside our control buffer. The
    // CMSG_* helpers stay within that buffer, and the timespec is read unaligned.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_TIMESTAMPNS {
                let ts: libc::timespec = ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
                let secs = u64::try_from(ts.tv_sec).ok()?;
                let nanos = u32::try_from(ts.tv_nsec).ok()?;
                return Some(UNIX_EPOCH + Duration::new(secs, nanos));
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

/// The `sock_extended_err` of an error-queue message and the offender
/// address after it.
fn extended_err_from_control(
    msg: &libc::msghdr,
    v6: bool,
) -> Option<(IcmpErrorKind, u8, u8, Option<IpAddr>)> {
    let (level, kind) = if v6 {
        (libc::SOL_IPV6, libc::IPV6_RECVERR)
    } else {
        (libc::SOL_IP, libc::IP_RECVERR)
    };
    // SAFETY: as in `timestamp_from_control`; the payload is a
    // sock_extended_err followed by the offender's sockaddr (SO_EE_OFFENDER),
    // both read unaligned and only when the cmsg is long enough to hold them.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;
            if hdr.cmsg_level == level && hdr.cmsg_type == kind {
                let data = libc::CMSG_DATA(cmsg);
                let header = data.offset_from(cmsg.cast::<u8>());
                let avail = (hdr.cmsg_len as usize).saturating_sub(usize::try_from(header).ok()?);
                let ee_len = mem::size_of::<libc::sock_extended_err>();
                if avail < ee_len {
                    return None;
                }
                let ee: libc::sock_extended_err = ptr::read_unaligned(data.cast());
                let icmp_origin = if v6 {
                    libc::SO_EE_ORIGIN_ICMP6
                } else {
                    libc::SO_EE_ORIGIN_ICMP
                };
                let kind = match (ee.ee_origin == icmp_origin, v6, ee.ee_type) {
                    (true, false, 11) | (true, true, 3) => IcmpErrorKind::TimeExceeded,
                    (true, false, 3) | (true, true, 1) => IcmpErrorKind::Unreachable,
                    _ => IcmpErrorKind::Other,
                };
                let mut offender = None;
                if avail >= ee_len + mem::size_of::<libc::sockaddr_in>() {
                    let mut storage: libc::sockaddr_storage = mem::zeroed();
                    let take = (avail - ee_len).min(mem::size_of::<libc::sockaddr_storage>());
                    ptr::copy_nonoverlapping(
                        data.add(ee_len),
                        ptr::from_mut(&mut storage).cast::<u8>(),
                        take,
                    );
                    offender = sockaddr_to_ip(&storage);
                }
                return Some((kind, ee.ee_type, ee.ee_code, offender));
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

/// # Safety
/// `storage` must be initialised, as filled in by the kernel.
unsafe fn sockaddr_to_ip(storage: &libc::sockaddr_storage) -> Option<IpAddr> {
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: the family says the storage holds a sockaddr_in, which fits in
            // sockaddr_storage; read_unaligned avoids any alignment assumption.
            let sin: libc::sockaddr_in =
                unsafe { ptr::read_unaligned(ptr::from_ref(storage).cast()) };
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            // SAFETY: as above, for sockaddr_in6.
            let sin6: libc::sockaddr_in6 =
                unsafe { ptr::read_unaligned(ptr::from_ref(storage).cast()) };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}
