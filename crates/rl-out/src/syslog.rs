//! `type = "syslog"`: RFC 5424 (or RFC 3164) messages over UDP (RFC 5426),
//! TCP (RFC 6587) or TLS (RFC 5425).
//!
//! ```text
//! <164>1 2026-11-21T10:05:00.000Z probe1 routelith 4242 alert_raised [routelith@32473 vantage="local" target="gw" family="v4" series="3" rule="loss" value="25"] gw (v4): loss raised: ...
//! ```
//!
//! The structured data carries the event's fields; MSG is the line people
//! read. The SD-ID uses enterprise number 32473 (RFC 5612, set aside for
//! examples) until Routelith has its own; `sd_id` changes it.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rl_core::output::{Framing, SyslogFormat, SyslogOutput, Transport};
use rl_core::silence::civil_from_days;
use rl_store::{Event, EventKind};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;

use crate::{Failure, IO_TIMEOUT, Sink};

const DAY_MS: i64 = 86_400_000;
/// The longest UDP message sent: what every receiver must take
/// (RFC 5426 §3.2 for RFC 5424; RFC 3164 §4.1 says 1024).
const UDP_MAX_5424: usize = 2048;
const UDP_MAX_3164: usize = 1024;
/// The longest a TLS handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The fixed parts of the messages of one output.
#[derive(Debug, Clone)]
pub struct Header {
    pub facility: u8,
    /// `-` when unknown.
    pub hostname: String,
    pub app_name: String,
    pub procid: u32,
    pub sd_id: String,
}

/// Severity (RFC 5424 §6.2.1) of an event kind.
fn severity(kind: EventKind) -> u8 {
    match kind {
        EventKind::AlertRaised
        | EventKind::AgentDisconnected
        | EventKind::AgentRevoked
        | EventKind::AgentClockSkew
        | EventKind::AgentRoundsLost => 4, // warning
        EventKind::AlertCleared
        | EventKind::IpChanged
        | EventKind::AgentConnected
        | EventKind::AgentClockOk => 5, // notice
        EventKind::ServerStarted
        | EventKind::ServerStopped
        | EventKind::AgentEnrolled
        | EventKind::Unknown => 6, // info
    }
}

/// `2026-11-21T10:05:00.123Z`.
pub(crate) fn rfc3339(ms: i64) -> String {
    let (y, m, d) = civil_from_days(ms.div_euclid(DAY_MS));
    let t = ms.rem_euclid(DAY_MS);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        t / 3_600_000,
        t / 60_000 % 60,
        t / 1000 % 60,
        t % 1000
    )
}

/// A PARAM-VALUE: `"`, `\` and `]` escaped (RFC 5424 §6.3.3), on one line.
fn sd_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '"' | '\\' | ']') {
            out.push('\\');
        }
        // Control characters (a line break could end an LF-framed message)
        // become spaces.
        out.push(if c.is_control() { ' ' } else { c });
    }
    out
}

/// The message for people, on one line.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// An RFC 5424 message (without framing).
pub fn format_rfc5424(e: &Event, h: &Header) -> String {
    let pri = u16::from(h.facility) * 8 + u16::from(severity(e.kind));
    let mut sd = format!("[{}", h.sd_id);
    let mut param = |name: &str, v: Option<String>| {
        if let Some(v) = v {
            sd += &format!(" {name}=\"{}\"", sd_value(&v));
        }
    };
    param("vantage", Some(e.vantage.clone()));
    param("target", e.target.clone());
    param("family", e.family.clone());
    param("series", e.series.map(|s| s.to_string()));
    param("rule", e.rule.clone());
    param("value", e.value.map(|v| v.to_string()));
    param("since", e.since.map(rfc3339));
    param("from", e.from.clone());
    param("to", e.to.clone());
    param("silenced_by", e.silenced_by.clone());
    param("suppressed_by", e.suppressed_by.clone());
    sd.push(']');
    let msg = one_line(&e.message);
    // MSG in UTF-8 starts with a BOM (§6.4); plain ASCII needs none.
    let bom = if msg.is_ascii() { "" } else { "\u{feff}" };
    format!(
        "<{pri}>1 {} {} {} {} {} {sd} {bom}{msg}",
        rfc3339(e.t),
        h.hostname,
        h.app_name,
        h.procid,
        e.kind.as_str(),
    )
}

/// An RFC 3164 message: `<PRI>Mmm dd hh:mm:ss HOST TAG[pid]: MSG`, with
/// the time in UTC (the format has no zone).
pub fn format_rfc3164(e: &Event, h: &Header) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let pri = u16::from(h.facility) * 8 + u16::from(severity(e.kind));
    let (_, m, d) = civil_from_days(e.t.div_euclid(DAY_MS));
    let t = e.t.rem_euclid(DAY_MS) / 1000;
    let month = MONTHS[usize::try_from(m - 1).unwrap_or(0)];
    let tag: String = h.app_name.chars().take(32).collect();
    // RFC 3164 has no "unknown" host; fall back to the address-less form.
    let host = if h.hostname == "-" {
        "localhost"
    } else {
        &h.hostname
    };
    format!(
        "<{pri}>{month} {d:>2} {:02}:{:02}:{:02} {host} {tag}[{}]: {}",
        t / 3600,
        t / 60 % 60,
        t % 60,
        h.procid,
        one_line(&e.message)
    )
}

/// The machine's host name, for HOSTNAME: printable ASCII without spaces,
/// or `None`.
pub fn machine_hostname() -> Option<String> {
    let from_file = |p: &str| std::fs::read_to_string(p).ok();
    let name = from_file("/proc/sys/kernel/hostname")
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| from_file("/etc/hostname"))?;
    let name = name.trim();
    (!name.is_empty() && name.len() <= 255 && name.bytes().all(|b| (33..=126).contains(&b)))
        .then(|| name.to_string())
}

/// Cut `s` to at most `max` bytes, on a character boundary.
fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
    }
    s
}

/// An open connection.
enum Conn {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

pub(crate) struct SyslogSink {
    cfg: SyslogOutput,
    header: Header,
    tls: Option<(Arc<ClientConfig>, ServerName<'static>)>,
    conn: Option<Conn>,
}

impl std::fmt::Debug for SyslogSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyslogSink")
            .field("host", &self.cfg.host)
            .field("port", &self.cfg.port)
            .field("transport", &self.cfg.transport)
            .field("connected", &self.conn.is_some())
            .finish()
    }
}

impl SyslogSink {
    /// `hostname` is the machine's, used unless the output sets one.
    pub(crate) fn new(cfg: &SyslogOutput, hostname: Option<&str>) -> Result<Self, String> {
        let tls = match cfg.transport {
            Transport::Tls => {
                let config = crate::tls::client_config(
                    cfg.ca_file.as_deref(),
                    cfg.cert_file.as_deref(),
                    cfg.key_file.as_deref(),
                )?;
                let name = cfg.server_name.clone().unwrap_or_else(|| cfg.host.clone());
                let name =
                    ServerName::try_from(name).map_err(|e| format!("TLS server name: {e}"))?;
                Some((config, name))
            }
            Transport::Udp | Transport::Tcp => None,
        };
        Ok(Self {
            header: Header {
                facility: cfg.facility,
                hostname: cfg
                    .hostname
                    .clone()
                    .or_else(|| hostname.map(str::to_string))
                    .unwrap_or_else(|| "-".to_string()),
                app_name: cfg.app_name.clone(),
                procid: std::process::id(),
                sd_id: cfg.sd_id.clone(),
            },
            cfg: cfg.clone(),
            tls,
            conn: None,
        })
    }

    fn addresses(&self) -> Result<Vec<SocketAddr>, String> {
        let addrs: Vec<SocketAddr> = (self.cfg.host.as_str(), self.cfg.port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {}: {e}", self.cfg.host))?
            .collect();
        if addrs.is_empty() {
            return Err(format!("{} has no address", self.cfg.host));
        }
        Ok(addrs)
    }

    fn tcp(a: SocketAddr) -> Result<TcpStream, String> {
        let s = TcpStream::connect_timeout(&a, IO_TIMEOUT)
            .map_err(|e| format!("cannot connect to {a}: {e}"))?;
        let _ = s.set_nodelay(true);
        s.set_write_timeout(Some(IO_TIMEOUT))
            .and_then(|()| s.set_read_timeout(Some(IO_TIMEOUT)))
            .map_err(|e| e.to_string())?;
        Ok(s)
    }

    /// Connect to one address of the receiver.
    fn connect_to(&self, a: SocketAddr) -> Result<Conn, String> {
        match self.cfg.transport {
            Transport::Udp => {
                let local: SocketAddr = if a.is_ipv4() {
                    ([0, 0, 0, 0], 0).into()
                } else {
                    ([0u16; 8], 0).into()
                };
                let s = UdpSocket::bind(local).map_err(|e| format!("UDP socket: {e}"))?;
                s.connect(a).map_err(|e| format!("cannot reach {a}: {e}"))?;
                Ok(Conn::Udp(s))
            }
            Transport::Tcp => Ok(Conn::Tcp(Self::tcp(a)?)),
            Transport::Tls => {
                let (config, name) = self.tls.clone().ok_or("no TLS configuration")?;
                let mut sock = Self::tcp(a)?;
                let mut c = ClientConnection::new(config, name).map_err(|e| format!("TLS: {e}"))?;
                handshake(&mut c, &mut sock, Instant::now() + HANDSHAKE_TIMEOUT)
                    .map_err(|e| format!("TLS handshake with {a}: {e}"))?;
                sock.set_write_timeout(Some(IO_TIMEOUT))
                    .and_then(|()| sock.set_read_timeout(Some(IO_TIMEOUT)))
                    .map_err(|e| e.to_string())?;
                Ok(Conn::Tls(Box::new(StreamOwned::new(c, sock))))
            }
        }
    }

    /// Connect to the first address of the receiver that works.
    fn connect(&self) -> Result<Conn, String> {
        let mut last = String::new();
        for a in self.addresses()? {
            match self.connect_to(a) {
                Ok(c) => return Ok(c),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn frame(&self, e: &Event) -> Vec<u8> {
        let msg = match self.cfg.format {
            SyslogFormat::Rfc5424 => format_rfc5424(e, &self.header),
            SyslogFormat::Rfc3164 => format_rfc3164(e, &self.header),
        };
        match (self.cfg.transport, self.cfg.framing) {
            (Transport::Udp, _) => {
                let max = match self.cfg.format {
                    SyslogFormat::Rfc5424 => UDP_MAX_5424,
                    SyslogFormat::Rfc3164 => UDP_MAX_3164,
                };
                truncate(msg, max).into_bytes()
            }
            (_, Framing::OctetCounting) => format!("{} {msg}", msg.len()).into_bytes(),
            (_, Framing::Lf) => format!("{msg}\n").into_bytes(),
        }
    }
}

/// Drive a TLS handshake one socket read or write at a time, each with
/// a timeout of what is left before `until`, so the whole handshake ends
/// by then even if the receiver trickles bytes.
pub(crate) fn handshake(
    c: &mut ClientConnection,
    sock: &mut TcpStream,
    until: Instant,
) -> io::Result<()> {
    let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "timed out");
    // A socket timeout shows as WouldBlock on Unix and TimedOut on Windows.
    let io = |r: io::Result<usize>| {
        r.map_err(|e| {
            if e.kind() == io::ErrorKind::WouldBlock {
                timed_out()
            } else {
                e
            }
        })
    };
    while c.is_handshaking() {
        let left = until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(timed_out)?;
        if c.wants_write() {
            sock.set_write_timeout(Some(left))?;
            io(c.write_tls(sock))?;
        } else if c.wants_read() {
            sock.set_read_timeout(Some(left))?;
            if io(c.read_tls(sock))? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the receiver closed the connection",
                ));
            }
            c.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        } else {
            break;
        }
    }
    // The last flight (client Finished) may still be queued.
    while c.wants_write() {
        let left = until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(timed_out)?;
        sock.set_write_timeout(Some(left))?;
        io(c.write_tls(sock))?;
    }
    Ok(())
}

/// Whether a stream the receiver may have closed is still open: a
/// receiver sends nothing, so end-of-stream or an error means it went
/// away. Without this check the first write after a close would vanish.
fn still_open<S: Read>(s: &mut S, sock: &TcpStream) -> bool {
    if sock.set_nonblocking(true).is_err() {
        return false;
    }
    let mut buf = [0u8; 256];
    let open = match s.read(&mut buf) {
        Ok(0) => false,
        Ok(_) => true,
        Err(e) => e.kind() == io::ErrorKind::WouldBlock,
    };
    sock.set_nonblocking(false).is_ok() && open
}

impl Sink for SyslogSink {
    fn deliver(&mut self, e: &Event) -> Result<(), Failure> {
        let bytes = self.frame(e);
        let open = match &mut self.conn {
            Some(Conn::Tcp(s)) => {
                let sock = s.try_clone().map_err(|e| e.to_string())?;
                still_open(s, &sock)
            }
            Some(Conn::Tls(s)) => {
                let sock = s.sock.try_clone().map_err(|e| e.to_string())?;
                still_open(s.as_mut(), &sock)
            }
            Some(Conn::Udp(_)) => true,
            None => false,
        };
        if !open {
            self.conn = Some(self.connect()?);
        }
        let to = format!("{}:{}", self.cfg.host, self.cfg.port);
        let r = match self.conn.as_mut() {
            Some(Conn::Udp(s)) => s.send(&bytes).map(|_| ()),
            Some(Conn::Tcp(s)) => s.write_all(&bytes).and_then(|()| s.flush()),
            Some(Conn::Tls(s)) => s.write_all(&bytes).and_then(|()| s.flush()),
            None => Ok(()),
        };
        r.map_err(|err| {
            Failure::Retry(format!(
                "cannot send to {to} ({}): {err}",
                self.cfg.transport.as_str()
            ))
        })
    }

    /// Drop the connection without flushing: buffered data of the event
    /// that failed must not go out, as it is sent again.
    fn reset(&mut self) {
        self.conn = None;
    }
}
