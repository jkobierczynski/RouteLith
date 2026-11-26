//! Outputs (architecture doc §11.2, §21.5 F7): where events go besides
//! the event log. Each `[[output]]` table names one, with a filter on the
//! events it takes. This version sends to syslog, to a JSON-lines file,
//! to webhooks, by e-mail and (on Windows) to the Windows Event Log.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::config::HttpUrl;
use crate::secret::Secret;

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
    /// The Windows Application log, source `Routelith` (doc §11.3, F8).
    EventLog,
    Webhook(WebhookOutput),
    Email(EmailOutput),
}

impl OutputKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            OutputKind::Syslog(_) => "syslog",
            OutputKind::Jsonl(_) => "jsonl",
            OutputKind::EventLog => "eventlog",
            OutputKind::Webhook(_) => "webhook",
            OutputKind::Email(_) => "email",
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
pub const EVENT_KINDS: [&str; 12] = [
    "alert_raised",
    "alert_cleared",
    "ip_changed",
    "server_started",
    "server_stopped",
    "agent_enrolled",
    "agent_connected",
    "agent_disconnected",
    "agent_revoked",
    "agent_clock_skew",
    "agent_clock_ok",
    "agent_rounds_lost",
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

/// An HTTP POST per event (doc §11.4, F10).
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookOutput {
    /// Where to POST; may hold a secret (a Slack URL is one), so messages
    /// name only its host.
    pub url: HttpUrl,
    pub format: WebhookFormat,
    /// `json` only: the key for the `X-Routelith-Signature` HMAC.
    pub secret: Option<Secret>,
    /// `ntfy` (bearer token) and `gotify` (application token) only.
    pub token: Option<Secret>,
    /// Added to the system's CAs for an `https` URL.
    pub ca_file: Option<PathBuf>,
}

impl fmt::Debug for WebhookOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookOutput")
            .field("host", &self.url.host)
            .field("port", &self.url.port)
            .field("tls", &self.url.tls)
            .field("format", &self.format)
            .field("secret", &self.secret)
            .field("token", &self.token)
            .field("ca_file", &self.ca_file)
            .finish()
    }
}

/// The body a webhook gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebhookFormat {
    /// The event as in the event log, optionally signed.
    Json,
    Slack,
    /// A Teams workflow ("When a Teams webhook request is received").
    Teams,
    Mattermost,
    Ntfy,
    Gotify,
}

impl WebhookFormat {
    pub const NAMES: [(&'static str, WebhookFormat); 6] = [
        ("json", WebhookFormat::Json),
        ("slack", WebhookFormat::Slack),
        ("teams", WebhookFormat::Teams),
        ("mattermost", WebhookFormat::Mattermost),
        ("ntfy", WebhookFormat::Ntfy),
        ("gotify", WebhookFormat::Gotify),
    ];
}

/// An e-mail per event over SMTP (doc §11.4, F10), with a PNG of the
/// series' smoke graph attached when the event has a series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailOutput {
    /// The SMTP server (a relay or submission server).
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    /// Log in with these; the password comes from `${env:}` or `${file:}`.
    pub username: Option<String>,
    pub password: Option<Secret>,
    /// `addr@example.net` or `Name <addr@example.net>`.
    pub from: String,
    pub to: Vec<String>,
    /// Added to the system's CAs.
    pub ca_file: Option<PathBuf>,
    /// The time span of the attached graph, ending when the mail is sent;
    /// `None`: no graph.
    pub graph: Option<Duration>,
}

/// How the SMTP connection is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// Plain connection upgraded with STARTTLS, which must succeed (port 587).
    StartTls,
    /// TLS from the first byte (port 465).
    Tls,
    /// No TLS (port 25); only allowed without a password or to a loopback
    /// server.
    None,
}

impl SmtpSecurity {
    pub const NAMES: [(&'static str, SmtpSecurity); 3] = [
        ("starttls", SmtpSecurity::StartTls),
        ("tls", SmtpSecurity::Tls),
        ("none", SmtpSecurity::None),
    ];

    pub fn default_port(self) -> u16 {
        match self {
            SmtpSecurity::StartTls => 587,
            SmtpSecurity::Tls => 465,
            SmtpSecurity::None => 25,
        }
    }
}

/// The attached graph covers this much unless `graph` says otherwise.
pub const DEFAULT_EMAIL_GRAPH: Duration = Duration::from_secs(3 * 3600);
