//! Outputs (architecture doc §11.2, §21.5 F7): where events go besides
//! the event log. Each `[[output]]` table names one, with a filter on the
//! events it takes. This version sends to syslog and to a JSON-lines file;
//! the Windows Event Log, webhooks and e-mail come later in M2.

use std::path::PathBuf;

/// One `[[output]]` table, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Unique among the outputs; used in `/metrics` labels and messages.
    pub name: String,
    pub kind: OutputKind,
    pub filter: EventFilter,
    /// Messages waiting to be sent before new ones are dropped.
    pub queue: usize,
    /// 1-based line of the table, for messages.
    pub line: usize,
}

/// Messages an output holds unless `queue` says otherwise.
pub const DEFAULT_QUEUE: usize = 1_000;
/// The most `queue` may be.
pub const MAX_QUEUE: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputKind {
    Syslog(SyslogOutput),
    Jsonl(JsonlOutput),
}

impl OutputKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            OutputKind::Syslog(_) => "syslog",
            OutputKind::Jsonl(_) => "jsonl",
        }
    }
}

/// Which events an output takes. An empty list takes everything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventFilter {
    /// Event kinds, as in the event log (`alert_raised`, ...).
    pub events: Vec<String>,
    /// Targets; an event without a target (server start) passes only
    /// when no targets or groups are listed.
    pub targets: Vec<String>,
    pub groups: Vec<String>,
    /// Alert rules; events that are not alerts pass this one.
    pub alerts: Vec<String>,
    /// Also send alerts raised under a silence or while the target's
    /// parent had an alert (and their clears). Off by default.
    pub quiet: bool,
}

/// The event kinds an `events` list may name.
pub const EVENT_KINDS: [&str; 5] = [
    "alert_raised",
    "alert_cleared",
    "ip_changed",
    "server_started",
    "server_stopped",
];

/// A syslog receiver (RFC 5424 or RFC 3164).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogOutput {
    /// Host name or address.
    pub host: String,
    pub port: u16,
    pub transport: Transport,
    pub format: SyslogFormat,
    /// 0 (kern) to 23 (local7).
    pub facility: u8,
    /// HOSTNAME field; the machine's name when unset.
    pub hostname: Option<String>,
    pub app_name: String,
    /// SD-ID of the structured data (RFC 5424 only).
    pub sd_id: String,
    pub framing: Framing,
    /// TLS: extra trusted CA certificates (PEM), on top of the system's.
    pub ca_file: Option<PathBuf>,
    /// TLS: a client certificate and its key (PEM), for receivers that
    /// want mutual authentication (RFC 5425 §5.3).
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    /// TLS: the name the certificate must carry, when not `host`.
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Tls => "tls",
        }
    }

    /// The registered port: 514 for UDP and TCP, 6514 for TLS.
    pub fn default_port(self) -> u16 {
        match self {
            Transport::Udp | Transport::Tcp => 514,
            Transport::Tls => 6514,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogFormat {
    Rfc5424,
    /// The old BSD format, for receivers that know no other.
    Rfc3164,
}

/// How messages are separated on a stream (TCP, TLS). UDP sends one per
/// datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// `LEN SP MSG` (RFC 6587 §3.4.1, RFC 5425 §4.3): the default.
    OctetCounting,
    /// MSG followed by LF (RFC 6587 §3.4.2), for old receivers.
    Lf,
}

/// Facility names and their numbers (RFC 5424 §6.2.1).
pub const FACILITIES: [(&str, u8); 24] = [
    ("kern", 0),
    ("user", 1),
    ("mail", 2),
    ("daemon", 3),
    ("auth", 4),
    ("syslog", 5),
    ("lpr", 6),
    ("news", 7),
    ("uucp", 8),
    ("cron", 9),
    ("authpriv", 10),
    ("ftp", 11),
    ("ntp", 12),
    ("security", 13),
    ("console", 14),
    ("solaris-cron", 15),
    ("local0", 16),
    ("local1", 17),
    ("local2", 18),
    ("local3", 19),
    ("local4", 20),
    ("local5", 21),
    ("local6", 22),
    ("local7", 23),
];

/// Appends one JSON object per event to a file. The file is opened for
/// each event, so logrotate may move it away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonlOutput {
    pub path: PathBuf,
}
