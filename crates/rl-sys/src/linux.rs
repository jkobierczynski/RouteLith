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
