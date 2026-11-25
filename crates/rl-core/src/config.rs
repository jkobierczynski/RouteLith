//! TOML configuration (architecture doc §13.1), M0 subset.
//!
//! Settings cascade `[defaults]` → `[[group]]` → `[[group.target]]`. Every
//! problem is reported with its line and column. Value problems are all
//! reported at once; a syntax or schema error (bad TOML, an unknown key, a
//! value of the wrong type) stops parsing before the values are checked.
//!
//! ```toml
//! [server]
//! data_dir = "/var/lib/routelith"
//!
//! [defaults]
//! step  = "300s"
//! pings = 20
//!
//! [[group]]
//! name = "Core"
//!
//!   [[group.target]]
//!   name = "core-fw"
//!   host = "10.0.0.1"
//! ```

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::ops::Range;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use toml::Spanned;

use crate::alert::{self, AlertRule, Metric, PatternType, RuleKind, Threshold};
use crate::duration;
use crate::output::{
    self, EmailOutput, EventFilter, Framing, JsonlOutput, Output, OutputKind, SmtpSecurity,
    SyslogFormat, SyslogOutput, Transport, WebhookFormat, WebhookOutput,
};
use crate::secret::Secret;
use crate::silence::{Silence, When};

/// Seconds in a day; steps must divide it so rounds stay aligned to UTC days.
const DAY_SECS: u64 = 86_400;
/// A type-specific output key: its name, where it is set (if it is) and
/// the types it applies to.
type KeyUse<'a> = (&'a str, Option<Range<usize>>, &'a [&'a str]);

/// The output types this version has.
const TYPES: [&str; 5] = ["syslog", "jsonl", "eventlog", "webhook", "email"];
/// The span of an e-mail's graph.
const MIN_EMAIL_GRAPH: Duration = Duration::from_secs(600);
const MAX_EMAIL_GRAPH: Duration = Duration::from_secs(30 * 86_400);
const DEFAULT_STEP: Duration = Duration::from_secs(300);
const DEFAULT_PINGS: u16 = 20;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_SIZE: u16 = 56;
const DEFAULT_MAX_PPS: u32 = 1_000;
/// The vantage of a configuration that names none.
pub const DEFAULT_VANTAGE: &str = "local";
const MAX_PINGS: i64 = 1_000;
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest ICMP payload that fits one IPv4 datagram.
const MAX_SIZE: i64 = 65_507;
/// Smallest payload: it carries the 8-byte nonce.
const MIN_SIZE: i64 = 8;
const MAX_NAME_LEN: usize = 64;
const AVAILABLE: &str = "this version measures \"icmp\", \"tcp\", \"dns\" and \"http\"";

/// A validated configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub server: ServerConfig,
    /// Targets measured from this vantage, in file order.
    pub targets: Vec<TargetConfig>,
    /// Alert rules, in file order (§21.5 F1).
    pub alerts: Vec<crate::alert::AlertRule>,
    /// Silences, in file order (§21.5 F6).
    pub silences: Vec<crate::silence::Silence>,
    /// Outputs, in file order (§21.5 F7).
    pub outputs: Vec<Output>,
    /// Service levels the SLA report checks, in file order (§21.5 F13).
    pub slas: Vec<Sla>,
}

/// A `[[sla]]` table: what its targets must reach each month.
#[derive(Debug, Clone, PartialEq)]
pub struct Sla {
    pub name: String,
    /// Targets it covers; with `groups` empty too, every target.
    pub targets: Vec<String>,
    pub groups: Vec<String>,
    /// Least share of rounds with a reply, in percent.
    pub availability: Option<f64>,
    /// Most loss over the month, in percent.
    pub loss: Option<f64>,
    /// Most latency at `percentile`, in microseconds.
    pub latency_us: Option<u32>,
    /// The percentile `latency` is checked at, 50 to 99.
    pub percentile: u8,
    /// Line of the table, for messages.
    pub line: usize,
}

impl Sla {
    /// Whether it covers `target` of `group`.
    pub fn covers(&self, target: &str, group: &str) -> bool {
        (self.targets.is_empty() && self.groups.is_empty())
            || self.targets.iter().any(|t| t == target)
            || self.groups.iter().any(|g| g == group)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub data_dir: PathBuf,
    /// Name of this vantage point; `local` unless set.
    pub vantage: String,
    /// Packets-per-second ceiling for the whole agent (§5.2).
    pub max_pps: u32,
    /// Address of the web UI, API and /metrics; `None` when turned off
    /// with `listen_ui = "off"`. Default 127.0.0.1:8080 (§21.3 E9).
    pub listen_ui: Option<std::net::SocketAddr>,
    /// The UI's users (§21.5 F11); `users.toml` in `data_dir` unless set.
    /// No file, or no users in it: no login.
    pub users_file: PathBuf,
    /// With users, callers who do not log in may still read (a wall
    /// display); they never write.
    pub anonymous: bool,
    /// Certificate and key for TLS on `listen_ui`.
    pub tls: Option<UiTls>,
    /// Where agents connect (gRPC with mutual TLS, §21.7 G2); `None`
    /// unless set.
    pub listen_agents: Option<std::net::SocketAddr>,
}

/// PEM files for TLS on the web UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiTls {
    /// The certificate chain, server certificate first.
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// The users file's name in `data_dir` unless `users_file` is set.
pub const DEFAULT_USERS_FILE: &str = "users.toml";

/// Where the web UI listens unless `listen_ui` says otherwise.
pub const DEFAULT_LISTEN_UI: &str = "127.0.0.1:8080";

/// One target, with every setting resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetConfig {
    /// Unique across the file; used by `ctl render --target`.
    pub id: String,
    pub group: String,
    /// Host name or address literal.
    pub host: String,
    pub family: Family,
    pub schedule: Schedule,
    /// What is measured and the probe's own settings.
    pub probe: ProbeConfig,
    /// Names of the alert rules that apply, from the `alerts` setting.
    pub alerts: Vec<String>,
    /// The target this one depends on (§21.5 F6): while it has an alert
    /// raised, this target's alerts are recorded as suppressed.
    pub parent: Option<String>,
    /// 1-based line of the target's table, for messages.
    pub line: usize,
}

/// The probe of a target and its settings (architecture doc §4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProbeConfig {
    /// ICMP echo with this many payload bytes.
    Icmp { payload_size: u16 },
    /// TCP connect time to `port` (§4.3).
    Tcp { port: u16, mode: TcpMode },
    /// One DNS query per sample to the target's server (§4.5).
    Dns(DnsConfig),
    /// One HTTP(S) request per sample on a fresh connection (§4.6).
    Http(HttpConfig),
}

/// An HTTP target's request and what counts as success (§4.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpConfig {
    /// The URL as configured.
    pub url: String,
    /// `https` when true, else `http`.
    pub tls: bool,
    /// Host name or address from the URL (no brackets), sent as the Host
    /// header and, unless `sni` overrides it, as the TLS server name.
    pub host: String,
    pub port: u16,
    /// Path and query, at least `/`.
    pub path: String,
    pub method: HttpMethod,
    /// Inclusive status ranges that count as success.
    pub expect_status: Vec<(u16, u16)>,
    /// The time stored as the sample.
    pub metric: HttpMetric,
    /// Regular expression the first `BODY_LIMIT` bytes of the body must match.
    pub body_regex: Option<String>,
    /// Verify the server certificate (on by default).
    pub tls_verify: bool,
    /// Extra PEM CA certificates to trust, besides the system's.
    pub ca_file: Option<PathBuf>,
    /// TLS server name to send instead of the URL's host.
    pub sni: Option<String>,
}

/// Bytes of an HTTP body read per sample (for `body_regex` and the
/// `total` time); the rest is not downloaded.
pub const BODY_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HttpMethod {
    #[default]
    Get,
    Head,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

/// Which HTTP time a sample stores (the others go to the phase timings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HttpMetric {
    /// Start of connect to the first response byte.
    #[default]
    Ttfb,
    /// Start of connect to the end of the body (up to `BODY_LIMIT`).
    Total,
    /// The TCP handshake.
    Connect,
    /// The TLS handshake (https only).
    Tls,
}

impl HttpMetric {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ttfb => "ttfb",
            Self::Total => "total",
            Self::Connect => "connect",
            Self::Tls => "tls",
        }
    }
}

/// The parts of an `http://` or `https://` URL a probe needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// `"99.9%"` as 99.9; `None` unless 0 to 100 with a `%`.
pub fn parse_percent(s: &str) -> Option<f64> {
    let v: f64 = s.trim().strip_suffix('%')?.trim().parse().ok()?;
    (v.is_finite() && (0.0..=100.0).contains(&v)).then_some(v)
}

/// Parse an absolute `http` or `https` URL without user info or fragment.
pub fn parse_http_url(url: &str) -> Result<HttpUrl, String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("must start with http:// or https://".into());
    };
    if url.contains('#') {
        return Err("must not contain a #fragment".into());
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("must not contain spaces or control characters".into());
    }
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(split);
    if authority.contains('@') {
        return Err("must not contain user info (put secrets elsewhere)".into());
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let end = v6.find(']').ok_or("has an unclosed [")?;
        let host = &v6[..end];
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(format!("[{host}] is not an IPv6 address"));
        }
        let after = &v6[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p),
            None if after.is_empty() => None,
            None => return Err("has text after ]".into()),
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err("has no host".into());
    }
    let port = match port {
        None => {
            if tls {
                443
            } else {
                80
            }
        }
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n >= 1 => n,
            _ => return Err(format!("port {p:?} is not a number from 1 to 65535")),
        },
    };
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    Ok(HttpUrl {
        tls,
        host: host.to_string(),
        port,
        path,
    })
}

/// Parse `"200-299"`, `"200"` or `"200, 301-302"` into inclusive ranges.
pub fn parse_status_ranges(s: &str) -> Result<Vec<(u16, u16)>, String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        let (lo, hi) = part.split_once('-').unwrap_or((part, part));
        let num = |x: &str| match x.trim().parse::<u16>() {
            Ok(n @ 100..=599) => Ok(n),
            _ => Err(format!("{x:?} is not an HTTP status from 100 to 599")),
        };
        let (lo, hi) = (num(lo)?, num(hi)?);
        if lo > hi {
            return Err(format!("range {part:?} runs backwards"));
        }
        out.push((lo, hi));
    }
    Ok(out)
}

/// A DNS target's query and its expected answer (§4.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsConfig {
    pub port: u16,
    /// Name to query; each `{rand}` becomes a fresh random label per sample,
    /// so resolver caches cannot answer.
    pub query: String,
    /// Record type, upper case (`A`, `AAAA`, `MX`, ...).
    pub qtype: String,
    pub transport: DnsTransport,
    /// Recursion desired (RD bit).
    pub recursion: bool,
    /// Expected response code, upper case (default `NOERROR`).
    pub expect_rcode: String,
    /// Expected answer set (record data as text, compared as a set,
    /// ignoring case and a trailing dot); `None` accepts any answer.
    pub expect_answers: Option<Vec<String>>,
}

/// How DNS queries travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DnsTransport {
    #[default]
    Udp,
    /// A fresh TCP connection per sample; the time includes the handshake.
    Tcp,
}

impl DnsTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// Record types a DNS target may query.
pub const DNS_QTYPES: &[&str] = &[
    "A", "AAAA", "CAA", "CNAME", "DNSKEY", "DS", "HTTPS", "MX", "NS", "PTR", "SOA", "SRV", "SVCB",
    "TXT",
];
/// Response codes a DNS target may expect.
pub const DNS_RCODES: &[&str] = &[
    "NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED",
];

impl ProbeConfig {
    /// The `probe` value that selects this probe.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Icmp { .. } => "icmp",
            Self::Tcp { .. } => "tcp",
            Self::Dns(_) => "dns",
            Self::Http(_) => "http",
        }
    }
}

/// What a TCP sample times (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TcpMode {
    /// From `connect()` until the handshake completes.
    #[default]
    Connect,
    /// From `connect()` until the server's first byte (SSH, SMTP banners).
    Banner,
}

impl TcpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Banner => "banner",
        }
    }
}

/// When and how often a target is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// One round every `step`, aligned to wall-clock multiples of it.
    pub step: Duration,
    /// Samples per round.
    pub pings: u16,
    /// Window the samples are spread over.
    pub spread: Duration,
    /// Per-sample timeout.
    pub timeout: Duration,
}

impl Schedule {
    /// Average packets per second this schedule sends for one series.
    pub fn pps(&self) -> f64 {
        f64::from(self.pings) / self.step.as_secs_f64()
    }
}

/// Address family of a target (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
    /// Two series, one per family.
    Both,
    /// IPv6 when the name has an AAAA record, else IPv4.
    PreferV6,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
            Self::Both => "both",
            Self::PreferV6 => "prefer-v6",
        }
    }

    /// Number of series the target produces.
    pub fn series(self) -> u32 {
        if self == Self::Both { 2 } else { 1 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// A problem in the file, with its 1-based position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{}:{}: {kind}: {}", self.line, self.column, self.message)
    }
}

/// The outcome of [`parse`]: the configuration when there were no errors,
/// and every diagnostic (errors and warnings) in file order.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub config: Option<Config>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Parsed {
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
    }
}

/// Parse and validate a configuration file's contents.
pub fn parse(src: &str) -> Parsed {
    let mut v = Validator {
        src,
        line_starts: line_starts(src),
        diagnostics: Vec::new(),
        errors: 0,
        alert_names: HashMap::new(),
    };
    let config = match toml::from_str::<RawConfig>(src) {
        Ok(raw) => v.config(raw),
        Err(e) => {
            let span = e.span().unwrap_or(0..0);
            v.error(&span, e.message().trim_end().to_string());
            None
        }
    };
    let mut diagnostics = v.diagnostics;
    diagnostics.sort_by_key(|d| (d.line, d.column));
    // A bad value in [defaults] or a group is reported where it is declared,
    // and again identically for each target that inherits it: keep one.
    diagnostics.dedup();
    let config = config.filter(|_| diagnostics.iter().all(|d| d.severity != Severity::Error));
    Parsed {
        config,
        diagnostics,
    }
}

// ---- raw file shape -------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    server: Spanned<RawServer>,
    defaults: Option<RawDefaults>,
    #[serde(default, rename = "group")]
    groups: Vec<Spanned<RawGroup>>,
    #[serde(default, rename = "alert")]
    alerts: Vec<Spanned<RawAlert>>,
    #[serde(default, rename = "silence")]
    silences: Vec<Spanned<RawSilence>>,
    #[serde(default, rename = "output")]
    outputs: Vec<Spanned<RawOutput>>,
    #[serde(default, rename = "sla")]
    slas: Vec<Spanned<RawSla>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSla {
    name: Spanned<String>,
    targets: Option<Spanned<Vec<String>>>,
    groups: Option<Spanned<Vec<String>>>,
    availability: Option<Spanned<String>>,
    loss: Option<Spanned<String>>,
    latency: Option<Spanned<String>>,
    percentile: Option<Spanned<i64>>,
    /// Free text for people; not used.
    #[allow(dead_code)]
    comment: Option<Spanned<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOutput {
    name: Spanned<String>,
    #[serde(rename = "type")]
    type_: Spanned<String>,
    // The filter.
    events: Option<Spanned<Vec<String>>>,
    targets: Option<Spanned<Vec<String>>>,
    groups: Option<Spanned<Vec<String>>>,
    alerts: Option<Spanned<Vec<String>>>,
    quiet: Option<Spanned<bool>>,
    queue: Option<Spanned<i64>>,
    // syslog
    address: Option<Spanned<String>>,
    transport: Option<Spanned<String>>,
    format: Option<Spanned<String>>,
    facility: Option<Spanned<String>>,
    hostname: Option<Spanned<String>>,
    app_name: Option<Spanned<String>>,
    sd_id: Option<Spanned<String>>,
    framing: Option<Spanned<String>>,
    ca_file: Option<Spanned<String>>,
    cert_file: Option<Spanned<String>>,
    key_file: Option<Spanned<String>>,
    server_name: Option<Spanned<String>>,
    // jsonl
    path: Option<Spanned<String>>,
    // webhook (also format and ca_file)
    url: Option<Spanned<String>>,
    secret: Option<Spanned<String>>,
    token: Option<Spanned<String>>,
    // email (also address and ca_file)
    security: Option<Spanned<String>>,
    username: Option<Spanned<String>>,
    password: Option<Spanned<String>>,
    from: Option<Spanned<String>>,
    to: Option<Spanned<Vec<String>>>,
    graph: Option<Spanned<String>>,
    /// Free text for people; not used.
    #[allow(dead_code)]
    comment: Option<Spanned<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSilence {
    name: Spanned<String>,
    targets: Option<Spanned<Vec<String>>>,
    groups: Option<Spanned<Vec<String>>>,
    alerts: Option<Spanned<Vec<String>>>,
    start: Option<Spanned<String>>,
    end: Option<Spanned<String>>,
    rrule: Option<Spanned<String>>,
    duration: Option<Spanned<String>>,
    /// Free text for people; not used.
    #[allow(dead_code)]
    comment: Option<Spanned<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAlert {
    name: Spanned<String>,
    // Threshold rules.
    metric: Option<Spanned<String>>,
    condition: Option<Spanned<String>>,
    #[serde(rename = "for")]
    for_: Option<Spanned<toml::Value>>,
    clear: Option<Spanned<String>>,
    // SmokePing pattern rules.
    #[serde(rename = "type")]
    type_: Option<Spanned<String>>,
    pattern: Option<Spanned<Vec<String>>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    data_dir: Spanned<String>,
    vantage: Option<Spanned<String>>,
    max_pps: Option<Spanned<i64>>,
    // Accepted so the doc's example loads; unused until M1.
    listen_ui: Option<Spanned<String>>,
    listen_agents: Option<Spanned<String>>,
    users_file: Option<Spanned<String>>,
    anonymous: Option<Spanned<bool>>,
    tls_cert: Option<Spanned<String>>,
    tls_key: Option<Spanned<String>>,
}

/// Settings that cascade. Repeated in each table below because serde's
/// `flatten` cannot be combined with `deny_unknown_fields`.
#[derive(Debug, Default, Clone)]
struct Settings {
    step: Option<Spanned<String>>,
    pings: Option<Spanned<i64>>,
    spread: Option<Spanned<String>>,
    timeout: Option<Spanned<String>>,
    size: Option<Spanned<i64>>,
    family: Option<Spanned<String>>,
    alerts: Option<Spanned<Vec<String>>>,
}

impl Settings {
    /// `self` with every unset field taken from `parent`.
    fn over(self, parent: &Settings) -> Settings {
        Settings {
            step: self.step.or_else(|| parent.step.clone()),
            pings: self.pings.or_else(|| parent.pings.clone()),
            spread: self.spread.or_else(|| parent.spread.clone()),
            timeout: self.timeout.or_else(|| parent.timeout.clone()),
            size: self.size.or_else(|| parent.size.clone()),
            family: self.family.or_else(|| parent.family.clone()),
            alerts: self.alerts.or_else(|| parent.alerts.clone()),
        }
    }
}

macro_rules! settings_struct {
    ($name:ident { $($extra:tt)* }) => {
        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $name {
            $($extra)*
            step: Option<Spanned<String>>,
            pings: Option<Spanned<i64>>,
            spread: Option<Spanned<String>>,
            timeout: Option<Spanned<String>>,
            size: Option<Spanned<i64>>,
            family: Option<Spanned<String>>,
            alerts: Option<Spanned<Vec<String>>>,
        }

        impl $name {
            fn settings(&self) -> Settings {
                Settings {
                    step: self.step.clone(),
                    pings: self.pings.clone(),
                    spread: self.spread.clone(),
                    timeout: self.timeout.clone(),
                    size: self.size.clone(),
                    family: self.family.clone(),
                    alerts: self.alerts.clone(),
                }
            }
        }
    };
}

settings_struct!(RawDefaults {});

settings_struct!(RawGroup {
    name: Spanned<String>,
    parent: Option<Spanned<String>>,
    vantages: Option<Spanned<Vec<String>>>,
    #[serde(default, rename = "target")]
    targets: Vec<Spanned<RawTarget>>,
});

settings_struct!(RawTarget {
    name: Spanned<String>,
    parent: Option<Spanned<String>>,
    host: Option<Spanned<String>>,
    probe: Option<Spanned<String>>,
    // Keys of the M1 probes (§13.1 example), accepted so that a target using
    // them gets "probe not available yet" instead of "unknown field".
    url: Option<Spanned<toml::Value>>,
    expect_status: Option<Spanned<toml::Value>>,
    metric: Option<Spanned<toml::Value>>,
    server: Option<Spanned<toml::Value>>,
    query: Option<Spanned<toml::Value>>,
    qtype: Option<Spanned<toml::Value>>,
    port: Option<Spanned<toml::Value>>,
    mode: Option<Spanned<toml::Value>>,
    transport: Option<Spanned<toml::Value>>,
    recursion: Option<Spanned<toml::Value>>,
    expect_rcode: Option<Spanned<toml::Value>>,
    expect_answers: Option<Spanned<toml::Value>>,
    method: Option<Spanned<toml::Value>>,
    body_regex: Option<Spanned<toml::Value>>,
    tls_verify: Option<Spanned<toml::Value>>,
    ca_file: Option<Spanned<toml::Value>>,
    sni: Option<Spanned<toml::Value>>,
});

// ---- validation -----------------------------------------------------------

struct Validator<'a> {
    src: &'a str,
    /// Byte offset of each line's start.
    line_starts: Vec<usize>,
    diagnostics: Vec<Diagnostic>,
    errors: usize,
    /// Alert rule names, and whether a target uses them.
    alert_names: HashMap<String, bool>,
}

impl Validator<'_> {
    fn push(&mut self, severity: Severity, span: &Range<usize>, message: String) {
        let (line, column) = self.position(span.start);
        if severity == Severity::Error {
            self.errors += 1;
        }
        self.diagnostics.push(Diagnostic {
            severity,
            line,
            column,
            message: escape_controls(&message),
        });
    }

    /// 1-based line and column (in characters) of a byte offset.
    fn position(&self, offset: usize) -> (usize, usize) {
        let offset = offset.min(self.src.len());
        let line = self.line_starts.partition_point(|&s| s <= offset);
        let start = self.line_starts[line - 1];
        let column = self.src.get(start..offset).map_or(0, |l| l.chars().count()) + 1;
        (line, column)
    }

    fn error(&mut self, span: &Range<usize>, message: impl Into<String>) {
        self.push(Severity::Error, span, message.into());
    }

    fn warning(&mut self, span: &Range<usize>, message: impl Into<String>) {
        self.push(Severity::Warning, span, message.into());
    }

    fn config(&mut self, raw: RawConfig) -> Option<Config> {
        let server_span = raw.server.span();
        let server = self.server(raw.server.into_inner());
        let defaults = raw
            .defaults
            .as_ref()
            .map_or_else(Settings::default, RawDefaults::settings);
        let vantage = server
            .as_ref()
            .map_or_else(|| DEFAULT_VANTAGE.to_string(), |s| s.vantage.clone());
        let alerts = self.alerts(&raw.alerts);
        self.check_layer(&defaults);

        let mut targets = Vec::new();
        let mut group_names: HashMap<String, Range<usize>> = HashMap::new();
        let mut target_names: HashMap<String, usize> = HashMap::new();
        // Each target's parent as written, with where it was written.
        let mut parents: Vec<(String, Spanned<String>, bool)> = Vec::new();
        for group in raw.groups {
            let group_span = group.span();
            let group = group.into_inner();
            let gname = group.name.get_ref().trim().to_string();
            if gname.is_empty() {
                self.error(&group.name.span(), "group name must not be empty");
            } else if let Some(first) = group_names.get(&gname) {
                let (line, _) = self.position(first.start);
                self.error(
                    &group.name.span(),
                    format!("duplicate group name {gname:?} (first defined on line {line})"),
                );
            } else {
                group_names.insert(gname.clone(), group.name.span());
            }

            let measured_here = match &group.vantages {
                Some(v) if !v.get_ref().iter().any(|n| n == &vantage) => {
                    self.warning(
                        &v.span(),
                        format!(
                            "group {gname:?} does not list this vantage ({:?}); its targets are not measured here",
                            vantage
                        ),
                    );
                    false
                }
                _ => true,
            };
            if group.targets.is_empty() {
                self.warning(&group_span, format!("group {gname:?} has no targets"));
            }

            let own = group.settings();
            self.check_layer(&own);
            let group_settings = own.over(&defaults);
            for target in group.targets {
                let span = target.span();
                let target = target.into_inner();
                let name = target.name.get_ref().clone();
                if let Some(&line) = target_names.get(&name) {
                    self.error(
                        &target.name.span(),
                        format!("duplicate target name {name:?} (first defined on line {line})"),
                    );
                } else {
                    target_names.insert(name, self.position(span.start).0);
                }
                let settings = target.settings().over(&group_settings);
                let parent = target.parent.clone().or_else(|| {
                    // A group's parent covers its other targets.
                    group
                        .parent
                        .clone()
                        .filter(|p| p.get_ref() != target.name.get_ref())
                });
                if let Some(p) = &parent {
                    parents.push((target.name.get_ref().clone(), p.clone(), measured_here));
                }
                let t = self.target(&target, &gname, &settings, span);
                if let (Some(mut t), true) = (t, measured_here) {
                    t.parent = parent.map(|p| p.into_inner());
                    targets.push(t);
                }
            }
        }

        self.parents(&parents, &target_names, &targets);
        let silences = self.silences(&raw.silences, &target_names, &group_names);
        let outputs = self.outputs(&raw.outputs, &target_names, &group_names);
        let slas = self.slas(&raw.slas, &target_names, &group_names);

        let server = server?;
        // Packets per day as integers (every step divides a day), so a
        // budget that is exactly full is not rejected by float rounding.
        let per_day: u64 = targets
            .iter()
            .map(|t| {
                let rounds = DAY_SECS / t.schedule.step.as_secs().max(1);
                u64::from(t.schedule.pings) * u64::from(t.family.series()) * rounds
            })
            .sum();
        if per_day > u64::from(server.max_pps) * DAY_SECS {
            #[allow(clippy::cast_precision_loss)]
            let pps = per_day as f64 / DAY_SECS as f64;
            self.error(
                &server_span,
                format!(
                    "the targets need {pps:.1} packets/s on average, above max_pps = {}; \
                     lengthen step, lower pings or raise max_pps",
                    server.max_pps
                ),
            );
        }
        let mut unused: Vec<_> = raw
            .alerts
            .iter()
            .filter(|a| self.alert_names.get(a.get_ref().name.get_ref()) == Some(&false))
            .map(|a| (a.get_ref().name.span(), a.get_ref().name.get_ref().clone()))
            .collect();
        unused.dedup_by(|a, b| a.1 == b.1);
        for (span, name) in unused {
            self.warning(
                &span,
                format!("alert {name:?} is not used by any target (add it to a target's alerts)"),
            );
        }
        Some(Config {
            server,
            targets,
            alerts,
            silences,
            outputs,
            slas,
        })
    }

    /// The `[[sla]]` tables (§21.5 F13).
    fn slas(
        &mut self,
        raw: &[Spanned<RawSla>],
        targets: &HashMap<String, usize>,
        groups: &HashMap<String, Range<usize>>,
    ) -> Vec<Sla> {
        let mut out = Vec::new();
        let mut first_line: HashMap<String, usize> = HashMap::new();
        for s in raw {
            let line = self.position(s.span().start).0;
            let errors_before = self.error_count();
            let span = s.span();
            let s = s.get_ref();
            let name = s.name.get_ref().clone();
            if !valid_name(&name) {
                self.error(&s.name.span(), name_rule("sla name"));
            } else if let Some(first) = first_line.get(&name) {
                self.error(
                    &s.name.span(),
                    format!("duplicate sla name {name:?} (first defined on line {first})"),
                );
            } else {
                first_line.insert(name.clone(), line);
            }
            let mut list =
                |v: &Option<Spanned<Vec<String>>>, what: &str, known: &dyn Fn(&str) -> bool| {
                    let Some(v) = v else {
                        return Vec::new();
                    };
                    for n in v.get_ref() {
                        if !known(n) {
                            self.error(&v.span(), format!("sla {name:?}: unknown {what} {n:?}"));
                        }
                    }
                    v.get_ref().clone()
                };
            let t = list(&s.targets, "target", &|n| targets.contains_key(n));
            let g = list(&s.groups, "group", &|n| groups.contains_key(n));
            let percent = |v: &Option<Spanned<String>>, key: &str, me: &mut Self| {
                let v = v.as_ref()?;
                match parse_percent(v.get_ref()) {
                    Some(p) => Some(p),
                    None => {
                        me.error(
                            &v.span(),
                            format!("sla {name:?}: {key} must be a percentage from 0% to 100%, as in \"99.9%\""),
                        );
                        None
                    }
                }
            };
            let availability = percent(&s.availability, "availability", self);
            let loss = percent(&s.loss, "loss", self);
            let latency_us = s.latency.as_ref().and_then(|v| {
                let d = self.duration("latency", v)?;
                match u32::try_from(d.as_micros()) {
                    Ok(us) if us > 0 => Some(us),
                    _ => {
                        self.error(
                            &v.span(),
                            format!("sla {name:?}: latency must be above 0 and below an hour"),
                        );
                        None
                    }
                }
            });
            let percentile = match &s.percentile {
                None => 95,
                Some(p) => match u8::try_from(*p.get_ref()) {
                    Ok(p) if (50..=99).contains(&p) => p,
                    _ => {
                        self.error(
                            &p.span(),
                            format!("sla {name:?}: percentile must be 50 to 99"),
                        );
                        95
                    }
                },
            };
            if let (Some(p), None) = (&s.percentile, &s.latency) {
                self.error(
                    &p.span(),
                    format!("sla {name:?}: percentile applies with latency only"),
                );
            }
            if s.availability.is_none() && s.loss.is_none() && s.latency.is_none() {
                self.error(
                    &span,
                    format!("sla {name:?} needs availability, loss or latency"),
                );
            }
            if self.error_count() == errors_before {
                out.push(Sla {
                    name,
                    targets: t,
                    groups: g,
                    availability,
                    loss,
                    latency_us,
                    percentile,
                    line,
                });
            }
        }
        out
    }

    /// `parent` settings: each names another target, and they form no loop.
    fn parents(
        &mut self,
        parents: &[(String, Spanned<String>, bool)],
        names: &HashMap<String, usize>,
        measured: &[TargetConfig],
    ) {
        let of: HashMap<&str, &str> = parents
            .iter()
            .map(|(child, p, _)| (child.as_str(), p.get_ref().as_str()))
            .collect();
        for (child, p, here) in parents {
            let name = p.get_ref();
            if name == child {
                self.error(
                    &p.span(),
                    format!("target {child:?} cannot be its own parent"),
                );
            } else if !names.contains_key(name) {
                self.error(
                    &p.span(),
                    format!("parent {name:?} of target {child:?} is not a target in this file"),
                );
            } else if *here && !measured.iter().any(|t| &t.id == name) {
                self.warning(
                    &p.span(),
                    format!(
                        "parent {name:?} of target {child:?} is not measured from this vantage, \
                         so it never suppresses its alerts here"
                    ),
                );
            } else {
                // Follow the chain: a loop comes back to `child`.
                let mut at = name.as_str();
                for _ in 0..of.len() {
                    match of.get(at) {
                        Some(&next) if next == child => {
                            self.error(
                                &p.span(),
                                format!("parents of target {child:?} form a loop through {name:?}"),
                            );
                            break;
                        }
                        Some(&next) => at = next,
                        None => break,
                    }
                }
            }
        }
    }

    /// The `[[silence]]` tables (§21.5 F6).
    fn silences(
        &mut self,
        raw: &[Spanned<RawSilence>],
        targets: &HashMap<String, usize>,
        groups: &HashMap<String, Range<usize>>,
    ) -> Vec<Silence> {
        let mut out = Vec::new();
        let mut first_line: HashMap<String, usize> = HashMap::new();
        for s in raw {
            let line = self.position(s.span().start).0;
            let errors_before = self.error_count();
            let s = s.get_ref();
            let name = s.name.get_ref().clone();
            if !valid_name(&name) {
                self.error(&s.name.span(), name_rule("silence name"));
            } else if let Some(first) = first_line.get(&name) {
                self.error(
                    &s.name.span(),
                    format!("duplicate silence name {name:?} (first defined on line {first})"),
                );
            } else {
                first_line.insert(name.clone(), line);
            }
            let alert_names = self.alert_names.clone();
            let mut list = |v: &Option<Spanned<Vec<String>>>,
                            what: &str,
                            known: &dyn Fn(&str) -> bool| {
                let Some(v) = v else {
                    return Vec::new();
                };
                for n in v.get_ref() {
                    if !known(n) {
                        self.error(&v.span(), format!("silence {name:?}: unknown {what} {n:?}"));
                    }
                }
                v.get_ref().clone()
            };
            let t = list(&s.targets, "target", &|n| targets.contains_key(n));
            let g = list(&s.groups, "group", &|n| groups.contains_key(n));
            let a = list(&s.alerts, "alert", &|n| alert_names.contains_key(n));
            let time =
                |v: &Option<Spanned<String>>, me: &mut Self, key: &str| -> Option<Option<i64>> {
                    match v {
                        None => Some(None),
                        Some(v) => match crate::silence::parse_time(v.get_ref()) {
                            Ok(t) => Some(Some(t)),
                            Err(e) => {
                                me.error(&v.span(), format!("{key}: {e}"));
                                None
                            }
                        },
                    }
                };
            let start = time(&s.start, self, "start");
            let end = time(&s.end, self, "end");
            if let (Some(Some(a)), Some(Some(b)), Some(e)) = (start, end, &s.end) {
                if b <= a {
                    self.error(
                        &e.span(),
                        format!("silence {name:?}: end must be after start"),
                    );
                }
            }
            let when = match (&s.rrule, &s.duration) {
                (Some(r), Some(d)) => {
                    let rule = match crate::silence::parse_rrule(r.get_ref()) {
                        Ok(rule) => Some(rule),
                        Err(e) => {
                            self.error(&r.span(), e);
                            None
                        }
                    };
                    let duration_ms = self.duration("duration", d).and_then(|v| {
                        let ms = i64::try_from(v.as_millis()).unwrap_or(i64::MAX);
                        if (60_000..=7 * 86_400_000).contains(&ms) {
                            Some(ms)
                        } else {
                            self.error(
                                &d.span(),
                                format!(
                                    "silence {name:?}: duration must be from 1m to 168h (a week)"
                                ),
                            );
                            None
                        }
                    });
                    match (rule, duration_ms, start, end) {
                        (Some(rule), Some(duration_ms), Some(start_ms), Some(end_ms)) => {
                            Some(When::Every {
                                rule,
                                duration_ms,
                                start_ms,
                                end_ms,
                            })
                        }
                        _ => None,
                    }
                }
                (Some(r), None) => {
                    self.error(
                        &r.span(),
                        format!("silence {name:?} has an rrule and needs a duration, as in \"2h\""),
                    );
                    None
                }
                (None, Some(d)) => {
                    self.error(
                        &d.span(),
                        format!("silence {name:?}: duration applies with an rrule only"),
                    );
                    None
                }
                (None, None) => match (start, end) {
                    (Some(Some(start_ms)), Some(Some(end_ms))) => {
                        Some(When::Once { start_ms, end_ms })
                    }
                    (Some(_), Some(_)) => {
                        self.error(
                            &s.name.span(),
                            format!(
                                "silence {name:?} needs a start and an end, or an rrule and a duration"
                            ),
                        );
                        None
                    }
                    _ => None,
                },
            };
            if let (Some(when), true) = (when, self.error_count() == errors_before) {
                out.push(Silence {
                    name,
                    targets: t,
                    groups: g,
                    alerts: a,
                    when,
                    line,
                });
            }
        }
        out
    }

    /// The `[[output]]` tables (§21.5 F7).
    fn outputs(
        &mut self,
        raw: &[Spanned<RawOutput>],
        targets: &HashMap<String, usize>,
        groups: &HashMap<String, Range<usize>>,
    ) -> Vec<Output> {
        let mut out = Vec::new();
        let mut first_line: HashMap<String, usize> = HashMap::new();
        // JSON-lines files, by the line of the output that writes each.
        let mut files: HashMap<PathBuf, usize> = HashMap::new();
        for o in raw {
            let line = self.position(o.span().start).0;
            let errors_before = self.error_count();
            let o = o.get_ref();
            let name = o.name.get_ref().clone();
            if !valid_name(&name) {
                self.error(&o.name.span(), name_rule("output name"));
            } else if let Some(first) = first_line.get(&name) {
                self.error(
                    &o.name.span(),
                    format!("duplicate output name {name:?} (first defined on line {first})"),
                );
            } else {
                first_line.insert(name.clone(), line);
            }

            let alert_names = self.alert_names.clone();
            let mut list =
                |v: &Option<Spanned<Vec<String>>>, what: &str, known: &dyn Fn(&str) -> bool| {
                    let Some(v) = v else {
                        return Vec::new();
                    };
                    for n in v.get_ref() {
                        if !known(n) {
                            self.error(&v.span(), format!("output {name:?}: unknown {what} {n:?}"));
                        }
                    }
                    v.get_ref().clone()
                };
            let filter = EventFilter {
                events: list(&o.events, "event kind", &|n| {
                    output::EVENT_KINDS.contains(&n)
                }),
                targets: list(&o.targets, "target", &|n| targets.contains_key(n)),
                groups: list(&o.groups, "group", &|n| groups.contains_key(n)),
                alerts: list(&o.alerts, "alert", &|n| alert_names.contains_key(n)),
                quiet: o.quiet.as_ref().is_some_and(|q| *q.get_ref()),
            };
            let queue = match &o.queue {
                None => output::DEFAULT_QUEUE,
                Some(q) => match usize::try_from(*q.get_ref()) {
                    Ok(n @ 1..=output::MAX_QUEUE) => n,
                    _ => {
                        self.error(
                            &q.span(),
                            format!("queue must be from 1 to {}", output::MAX_QUEUE),
                        );
                        output::DEFAULT_QUEUE
                    }
                },
            };

            // Each type-specific key and the types it applies to.
            let keys: [KeyUse; 22] = [
                (
                    "address",
                    o.address.as_ref().map(Spanned::span),
                    &["syslog", "email"],
                ),
                (
                    "transport",
                    o.transport.as_ref().map(Spanned::span),
                    &["syslog"],
                ),
                (
                    "format",
                    o.format.as_ref().map(Spanned::span),
                    &["syslog", "webhook"],
                ),
                (
                    "facility",
                    o.facility.as_ref().map(Spanned::span),
                    &["syslog"],
                ),
                (
                    "hostname",
                    o.hostname.as_ref().map(Spanned::span),
                    &["syslog"],
                ),
                (
                    "app_name",
                    o.app_name.as_ref().map(Spanned::span),
                    &["syslog"],
                ),
                ("sd_id", o.sd_id.as_ref().map(Spanned::span), &["syslog"]),
                (
                    "framing",
                    o.framing.as_ref().map(Spanned::span),
                    &["syslog"],
                ),
                (
                    "cert_file",
                    o.cert_file.as_ref().map(Spanned::span),
                    &["syslog"],
                ),
                (
                    "key_file",
                    o.key_file.as_ref().map(Spanned::span),
                    &["syslog"],
                ),
                (
                    "server_name",
                    o.server_name.as_ref().map(Spanned::span),
                    &["syslog"],
                ),
                (
                    "ca_file",
                    o.ca_file.as_ref().map(Spanned::span),
                    &["syslog", "webhook", "email"],
                ),
                ("path", o.path.as_ref().map(Spanned::span), &["jsonl"]),
                ("url", o.url.as_ref().map(Spanned::span), &["webhook"]),
                ("secret", o.secret.as_ref().map(Spanned::span), &["webhook"]),
                ("token", o.token.as_ref().map(Spanned::span), &["webhook"]),
                (
                    "security",
                    o.security.as_ref().map(Spanned::span),
                    &["email"],
                ),
                (
                    "username",
                    o.username.as_ref().map(Spanned::span),
                    &["email"],
                ),
                (
                    "password",
                    o.password.as_ref().map(Spanned::span),
                    &["email"],
                ),
                ("from", o.from.as_ref().map(Spanned::span), &["email"]),
                ("to", o.to.as_ref().map(Spanned::span), &["email"]),
                ("graph", o.graph.as_ref().map(Spanned::span), &["email"]),
            ];
            let ty = o.type_.get_ref().as_str();
            if TYPES.contains(&ty) {
                for (key, span, types) in &keys {
                    if let (Some(span), false) = (span, types.contains(&ty)) {
                        let list = types
                            .iter()
                            .map(|t| format!("\"{t}\""))
                            .collect::<Vec<_>>()
                            .join(" or ");
                        self.error(
                            span,
                            format!("output {name:?}: {key} applies to type = {list} only"),
                        );
                    }
                }
            }
            let kind = match o.type_.get_ref().as_str() {
                "syslog" => self.syslog_output(&name, o).map(OutputKind::Syslog),
                "jsonl" => {
                    match &o.path {
                        Some(p) if !p.get_ref().trim().is_empty() => {
                            let path = PathBuf::from(p.get_ref());
                            if let Some(first) = files.get(&path) {
                                // Two writers would interleave their lines.
                                self.error(
                                    &p.span(),
                                    format!(
                                        "output {name:?}: the output on line {first} already \
                                         writes this file"
                                    ),
                                );
                            } else {
                                files.insert(path.clone(), line);
                            }
                            Some(OutputKind::Jsonl(JsonlOutput { path }))
                        }
                        Some(p) => {
                            self.error(&p.span(), format!("output {name:?}: path is empty"));
                            None
                        }
                        None => {
                            self.error(
                                &o.type_.span(),
                                format!("output {name:?} needs a path for the JSON lines file"),
                            );
                            None
                        }
                    }
                }
                "eventlog" => {
                    if cfg!(windows) {
                        Some(OutputKind::EventLog)
                    } else {
                        self.error(
                            &o.type_.span(),
                            format!(
                                "output {name:?}: the Windows Event Log exists only on Windows"
                            ),
                        );
                        None
                    }
                }
                "webhook" => self.webhook_output(&name, o).map(OutputKind::Webhook),
                "email" => self.email_output(&name, o).map(OutputKind::Email),
                t => {
                    self.error(
                        &o.type_.span(),
                        format!(
                            "unknown output type {t:?}; this version sends to \"syslog\", \
                             \"jsonl\", \"eventlog\", \"webhook\" and \"email\""
                        ),
                    );
                    None
                }
            };
            if let (Some(kind), true) = (kind, self.error_count() == errors_before) {
                out.push(Output {
                    name,
                    kind,
                    filter,
                    queue,
                    line,
                });
            }
        }
        out
    }

    /// The syslog settings of an `[[output]]`.
    /// A `${env:…}`/`${file:…}` value, expanded; errors at its span.
    fn secret_value(&mut self, name: &str, key: &str, v: &Spanned<String>) -> Option<String> {
        match crate::secret::expand(v.get_ref()) {
            Ok(s) => Some(s),
            Err(e) => {
                self.error(&v.span(), format!("output {name:?}: {key} {e}"));
                None
            }
        }
    }

    fn webhook_output(&mut self, name: &str, o: &RawOutput) -> Option<WebhookOutput> {
        let errors_before = self.error_count();
        let format = match &o.format {
            None => WebhookFormat::Json,
            Some(f) => match WebhookFormat::NAMES.iter().find(|(n, _)| n == f.get_ref()) {
                Some(&(_, w)) => w,
                None => {
                    self.error(
                        &f.span(),
                        format!(
                            "output {name:?}: format {:?} is not one of json, slack, teams, \
                             mattermost, ntfy, gotify",
                            f.get_ref()
                        ),
                    );
                    WebhookFormat::Json
                }
            },
        };
        let url = match &o.url {
            None => {
                self.error(
                    &o.type_.span(),
                    format!("output {name:?} needs the url to POST to"),
                );
                None
            }
            // The URL may hold a secret (a Slack or Teams URL is one), so
            // errors do not repeat it.
            Some(u) => self
                .secret_value(name, "url", u)
                .and_then(|v| match parse_http_url(&v) {
                    Ok(url) => Some(url),
                    Err(e) => {
                        // Parser errors may quote part of the value; one
                        // read from a reference is not repeated.
                        let msg = if v == *u.get_ref() {
                            format!("output {name:?}: url {e}")
                        } else {
                            format!(
                                "output {name:?}: url is not a valid http:// or https:// URL \
                                 once its references are filled in"
                            )
                        };
                        self.error(&u.span(), msg);
                        None
                    }
                }),
        };
        let secret = o.secret.as_ref().and_then(|s| {
            if format != WebhookFormat::Json {
                self.error(
                    &s.span(),
                    format!("output {name:?}: secret applies to format = \"json\" only"),
                );
            }
            self.secret_value(name, "secret", s)
        });
        if let Some(s) = &secret {
            if s.is_empty() {
                self.error(
                    &o.secret.as_ref().map(Spanned::span).unwrap_or_default(),
                    format!("output {name:?}: secret is empty"),
                );
            }
        }
        let token = o.token.as_ref().and_then(|t| {
            if !matches!(format, WebhookFormat::Ntfy | WebhookFormat::Gotify) {
                self.error(
                    &t.span(),
                    format!(
                        "output {name:?}: token applies to format = \"ntfy\" or \"gotify\" only"
                    ),
                );
            }
            let v = self.secret_value(name, "token", t)?;
            // It goes into an HTTP header.
            if v.is_empty() || v.chars().any(|c| c.is_control() || !c.is_ascii()) {
                self.error(
                    &t.span(),
                    format!("output {name:?}: token must be non-empty printable ASCII"),
                );
            }
            Some(v)
        });
        // A token sent in clear can be read and reused by anyone on the
        // path; only a loopback receiver is exempt.
        if let (Some(t), Some(u)) = (&o.token, &url) {
            if !u.tls && !loopback_host(&u.host) {
                self.error(
                    &t.span(),
                    format!(
                        "output {name:?}: token needs an https:// url (or a loopback \
                         host), so it is not sent in clear"
                    ),
                );
            }
        }
        if let (Some(c), Some(u)) = (&o.ca_file, &url) {
            if !u.tls {
                self.error(
                    &c.span(),
                    format!("output {name:?}: ca_file applies to an https:// url only"),
                );
            }
        }
        if self.error_count() != errors_before {
            return None;
        }
        Some(WebhookOutput {
            url: url?,
            format,
            secret: secret.map(Secret::new),
            token: token.map(Secret::new),
            ca_file: o.ca_file.as_ref().map(|c| PathBuf::from(c.get_ref())),
        })
    }

    fn email_output(&mut self, name: &str, o: &RawOutput) -> Option<EmailOutput> {
        let errors_before = self.error_count();
        let security = match &o.security {
            None => SmtpSecurity::StartTls,
            Some(v) => match SmtpSecurity::NAMES.iter().find(|(n, _)| n == v.get_ref()) {
                Some(&(_, s)) => s,
                None => {
                    self.error(
                        &v.span(),
                        format!(
                            "output {name:?}: security {:?} is not \"starttls\", \"tls\" or \
                             \"none\"",
                            v.get_ref()
                        ),
                    );
                    SmtpSecurity::StartTls
                }
            },
        };
        let address = match &o.address {
            None => {
                self.error(
                    &o.type_.span(),
                    format!(
                        "output {name:?} needs the address of the SMTP server, as in \
                         \"smtp.example.net:587\""
                    ),
                );
                None
            }
            Some(a) => match split_address(a.get_ref(), security.default_port()) {
                Ok(hp) => Some(hp),
                Err(e) => {
                    self.error(&a.span(), format!("output {name:?}: address: {e}"));
                    None
                }
            },
        };
        if let Some(u) = &o.username {
            let v = u.get_ref();
            if v.is_empty() || v.chars().any(char::is_control) {
                self.error(
                    &u.span(),
                    format!(
                        "output {name:?}: username must be non-empty, without control characters"
                    ),
                );
            }
        }
        let password = o.password.as_ref().and_then(|p| {
            // §14: no passwords in the configuration file itself.
            if !p.get_ref().contains("${") {
                self.error(
                    &p.span(),
                    format!(
                        "output {name:?}: password must come from ${{env:NAME}} or \
                         ${{file:/path}}, not the configuration file"
                    ),
                );
                return None;
            }
            let v = self.secret_value(name, "password", p)?;
            if v.is_empty() {
                self.error(&p.span(), format!("output {name:?}: password is empty"));
            }
            Some(v)
        });
        match (&o.username, &o.password) {
            (Some(u), None) => self.error(
                &u.span(),
                format!("output {name:?}: username needs a password"),
            ),
            (None, Some(p)) => self.error(
                &p.span(),
                format!("output {name:?}: password needs a username"),
            ),
            _ => {}
        }
        // A password sent in clear can be read and reused by anyone on the
        // path; only a loopback server is exempt.
        if let (Some(p), Some((host, _)), SmtpSecurity::None) = (&o.password, &address, security) {
            if !loopback_host(host) {
                self.error(
                    &p.span(),
                    format!(
                        "output {name:?}: a password needs security = \"starttls\" or \"tls\" \
                         (or a loopback server), so it is not sent in clear"
                    ),
                );
            }
        }
        if let (Some(c), SmtpSecurity::None) = (&o.ca_file, security) {
            self.error(
                &c.span(),
                format!(
                    "output {name:?}: ca_file applies to security \"starttls\" or \"tls\" only"
                ),
            );
        }
        let from = match &o.from {
            None => {
                self.error(
                    &o.type_.span(),
                    format!("output {name:?} needs a from address"),
                );
                None
            }
            Some(f) => {
                if let Err(e) = check_mailbox(f.get_ref()) {
                    self.error(&f.span(), format!("output {name:?}: from {e}"));
                }
                Some(f.get_ref().clone())
            }
        };
        let to = match &o.to {
            Some(t) if !t.get_ref().is_empty() => {
                for a in t.get_ref() {
                    if let Err(e) = check_mailbox(a) {
                        self.error(&t.span(), format!("output {name:?}: to {e}"));
                    }
                }
                t.get_ref().clone()
            }
            Some(t) => {
                self.error(&t.span(), format!("output {name:?}: to is empty"));
                Vec::new()
            }
            None => {
                self.error(
                    &o.type_.span(),
                    format!("output {name:?} needs to = [\"someone@example.net\", ...]"),
                );
                Vec::new()
            }
        };
        let graph = match &o.graph {
            None => Some(output::DEFAULT_EMAIL_GRAPH),
            Some(g) if g.get_ref() == "off" => None,
            Some(g) => match self.duration("graph", g) {
                Some(d) if (MIN_EMAIL_GRAPH..=MAX_EMAIL_GRAPH).contains(&d) => Some(d),
                Some(_) => {
                    self.error(
                        &g.span(),
                        format!("output {name:?}: graph must be from 10m to 30d, or \"off\""),
                    );
                    None
                }
                None => None,
            },
        };
        if self.error_count() != errors_before {
            return None;
        }
        let (host, port) = address?;
        Some(EmailOutput {
            host,
            port,
            security,
            username: o.username.as_ref().map(|u| u.get_ref().clone()),
            password: password.map(Secret::new),
            from: from?,
            to,
            ca_file: o.ca_file.as_ref().map(|c| PathBuf::from(c.get_ref())),
            graph,
        })
    }

    fn syslog_output(&mut self, name: &str, o: &RawOutput) -> Option<SyslogOutput> {
        let errors_before = self.error_count();
        let transport = match o.transport.as_ref().map(|t| (t, t.get_ref().as_str())) {
            None | Some((_, "udp")) => Transport::Udp,
            Some((_, "tcp")) => Transport::Tcp,
            Some((_, "tls")) => Transport::Tls,
            Some((t, v)) => {
                self.error(
                    &t.span(),
                    format!("output {name:?}: transport {v:?} is not \"udp\", \"tcp\" or \"tls\""),
                );
                Transport::Udp
            }
        };
        let format = match o.format.as_ref().map(|t| (t, t.get_ref().as_str())) {
            None | Some((_, "rfc5424")) => SyslogFormat::Rfc5424,
            Some((_, "rfc3164")) => SyslogFormat::Rfc3164,
            Some((t, v)) => {
                self.error(
                    &t.span(),
                    format!("output {name:?}: format {v:?} is not \"rfc5424\" or \"rfc3164\""),
                );
                SyslogFormat::Rfc5424
            }
        };
        let framing = match o.framing.as_ref().map(|t| (t, t.get_ref().as_str())) {
            None | Some((_, "octet-counting")) => Framing::OctetCounting,
            Some((_, "lf")) => Framing::Lf,
            Some((t, v)) => {
                self.error(
                    &t.span(),
                    format!("output {name:?}: framing {v:?} is not \"octet-counting\" or \"lf\""),
                );
                Framing::OctetCounting
            }
        };
        if let (Some(f), Transport::Udp) = (&o.framing, transport) {
            self.error(
                &f.span(),
                format!("output {name:?}: framing applies to transport \"tcp\" or \"tls\" only"),
            );
        }
        for (key, v) in [
            ("ca_file", &o.ca_file),
            ("cert_file", &o.cert_file),
            ("key_file", &o.key_file),
            ("server_name", &o.server_name),
        ] {
            if let (Some(v), false) = (v, transport == Transport::Tls) {
                self.error(
                    &v.span(),
                    format!("output {name:?}: {key} applies to transport = \"tls\" only"),
                );
            }
        }
        match (&o.cert_file, &o.key_file) {
            (Some(c), None) => self.error(
                &c.span(),
                format!("output {name:?}: cert_file needs a key_file"),
            ),
            (None, Some(k)) => self.error(
                &k.span(),
                format!("output {name:?}: key_file needs a cert_file"),
            ),
            _ => {}
        }
        let facility = match &o.facility {
            None => 16,
            Some(f) => match output::FACILITIES.iter().find(|(n, _)| n == f.get_ref()) {
                Some(&(_, n)) => n,
                None => {
                    self.error(
                        &f.span(),
                        format!(
                            "output {name:?}: unknown facility {:?} (use one of kern, user, \
                             daemon, ..., local0 to local7)",
                            f.get_ref()
                        ),
                    );
                    16
                }
            },
        };
        // HOSTNAME, APP-NAME and the SD-ID are printable ASCII without
        // spaces (RFC 5424 §6); the SD-ID also has no '=', ']' or '"'.
        let token =
            |me: &mut Self, v: &Option<Spanned<String>>, key: &str, max: usize, sd: bool| {
                let v = v.as_ref()?;
                let s = v.get_ref();
                let ok = !s.is_empty()
                    && s.len() <= max
                    && s.bytes().all(|b| (33..=126).contains(&b))
                    && !(sd && s.bytes().any(|b| matches!(b, b'=' | b']' | b'"')));
                if !ok {
                    me.error(
                        &v.span(),
                        format!(
                            "output {name:?}: {key} must be 1 to {max} printable ASCII characters \
                         without spaces{}",
                            if sd { ", '=', ']' or '\"'" } else { "" }
                        ),
                    );
                }
                Some(s.clone())
            };
        let hostname = token(self, &o.hostname, "hostname", 255, false);
        let app_name = token(self, &o.app_name, "app_name", 48, false)
            .unwrap_or_else(|| "routelith".to_string());
        let sd_id = token(self, &o.sd_id, "sd_id", 32, true)
            .unwrap_or_else(|| "routelith@32473".to_string());
        // Names without '@' are for IANA (RFC 5424 §7.2.2).
        let qualified = sd_id.split_once('@').is_some_and(|(n, pen)| {
            !n.is_empty() && !pen.is_empty() && pen.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        });
        if let (Some(v), false) = (&o.sd_id, qualified) {
            self.error(
                &v.span(),
                format!(
                    "output {name:?}: sd_id must be name@enterprise-number, as in \"routelith@32473\""
                ),
            );
        }
        // An RFC 3164 TAG ends at the first character that is not a letter
        // or digit.
        if let (Some(v), SyslogFormat::Rfc3164) = (&o.app_name, format) {
            let a = v.get_ref();
            if a.len() > 32 || !a.bytes().all(|b| b.is_ascii_alphanumeric()) {
                self.error(
                    &v.span(),
                    format!(
                        "output {name:?}: with format = \"rfc3164\", app_name must be 1 to 32 \
                         letters or digits"
                    ),
                );
            }
        }
        if let Some(v) = &o.server_name {
            if !valid_hostname(v.get_ref()) || numeric_tld(v.get_ref()) {
                self.error(
                    &v.span(),
                    format!("output {name:?}: server_name is not a valid host name"),
                );
            }
        }
        let Some(address) = &o.address else {
            self.error(
                &o.type_.span(),
                format!("output {name:?} needs an address, as in \"syslog.example.net:514\""),
            );
            return None;
        };
        let (host, port) = match split_address(address.get_ref(), transport.default_port()) {
            Ok(hp) => hp,
            Err(e) => {
                self.error(&address.span(), format!("output {name:?}: address: {e}"));
                return None;
            }
        };
        // A certificate names a DNS name or an address; a name whose last
        // label is all digits is neither.
        if transport == Transport::Tls && o.server_name.is_none() && numeric_tld(&host) {
            self.error(
                &address.span(),
                format!(
                    "output {name:?}: {host:?} cannot be checked against a certificate; \
                     set server_name"
                ),
            );
        }
        let path = |v: &Option<Spanned<String>>| v.as_ref().map(|v| PathBuf::from(v.get_ref()));
        (self.error_count() == errors_before).then(|| SyslogOutput {
            host,
            port,
            transport,
            format,
            facility,
            hostname,
            app_name,
            sd_id,
            framing,
            ca_file: path(&o.ca_file),
            cert_file: path(&o.cert_file),
            key_file: path(&o.key_file),
            server_name: o.server_name.as_ref().map(|v| v.get_ref().clone()),
        })
    }

    /// The `[[alert]]` tables (§21.5 F1–F3). Names are recorded even for a
    /// rule with errors, so targets naming it get no second error.
    fn alerts(&mut self, raw: &[Spanned<RawAlert>]) -> Vec<AlertRule> {
        let mut out = Vec::new();
        let mut first_line: HashMap<String, usize> = HashMap::new();
        for a in raw {
            let line = self.position(a.span().start).0;
            let a = a.get_ref();
            let name = a.name.get_ref().clone();
            if !valid_name(&name) {
                self.error(&a.name.span(), name_rule("alert name"));
                continue;
            }
            if let Some(first) = first_line.get(&name) {
                self.error(
                    &a.name.span(),
                    format!("duplicate alert name {name:?} (first defined on line {first})"),
                );
                continue;
            }
            first_line.insert(name.clone(), line);
            self.alert_names.insert(name.clone(), false);
            if let Some(kind) = self.alert_kind(a) {
                out.push(AlertRule { name, kind, line });
            }
        }
        out
    }

    fn alert_kind(&mut self, a: &RawAlert) -> Option<RuleKind> {
        let name = a.name.get_ref();
        if let Some(pattern) = &a.pattern {
            for (key, span) in [
                ("metric", a.metric.as_ref().map(Spanned::span)),
                ("condition", a.condition.as_ref().map(Spanned::span)),
                ("for", a.for_.as_ref().map(Spanned::span)),
                ("clear", a.clear.as_ref().map(Spanned::span)),
            ] {
                if let Some(span) = span {
                    self.error(
                        &span,
                        format!(
                            "{key} does not apply to a pattern rule; a pattern raises the alert \
                             while it matches"
                        ),
                    );
                }
            }
            let kind = match a.type_.as_ref().map(|t| (t, t.get_ref().as_str())) {
                Some((_, "loss")) => PatternType::Loss,
                Some((_, "rtt")) => PatternType::Rtt,
                Some((t, other)) => {
                    self.error(
                        &t.span(),
                        format!("unknown alert type {other:?}; use \"loss\" or \"rtt\""),
                    );
                    return None;
                }
                None => {
                    self.error(
                        &a.name.span(),
                        format!(
                            "alert {name:?} has a pattern and needs type = \"loss\" or \"rtt\""
                        ),
                    );
                    return None;
                }
            };
            return match alert::parse_pattern(pattern.get_ref(), kind) {
                Ok(p) => Some(RuleKind::Pattern(p)),
                Err(e) => {
                    self.error(&pattern.span(), e);
                    None
                }
            };
        }
        if let Some(t) = &a.type_ {
            self.error(
                &t.span(),
                "type applies to pattern rules only; a threshold rule names a metric",
            );
        }
        let Some(metric_raw) = &a.metric else {
            self.error(
                &a.name.span(),
                format!("alert {name:?} needs either metric and condition, or type and pattern"),
            );
            return None;
        };
        let Some(metric) = Metric::parse(metric_raw.get_ref()) else {
            let names: Vec<&str> = Metric::ALL.iter().map(|m| m.as_str()).collect();
            self.error(
                &metric_raw.span(),
                format!(
                    "unknown metric {:?}; use one of {}",
                    metric_raw.get_ref(),
                    names.join(", ")
                ),
            );
            return None;
        };
        let condition = match &a.condition {
            None => {
                self.error(&a.name.span(), format!("alert {name:?} needs a condition"));
                None
            }
            Some(c) => match alert::parse_condition(c.get_ref(), metric) {
                Ok(c) => Some(c),
                Err(e) => {
                    self.error(&c.span(), e);
                    None
                }
            },
        };
        let for_rounds = match &a.for_ {
            None => Some(1),
            Some(v) => {
                let text = match v.get_ref() {
                    toml::Value::String(s) => Ok(s.clone()),
                    toml::Value::Integer(i) => Ok(i.to_string()),
                    _ => Err(()),
                };
                match text
                    .map_err(|()| "for must be a number of rounds, as in \"3 rounds\"".to_string())
                    .and_then(|t| alert::parse_rounds(&t).map_err(|e| format!("for: {e}")))
                {
                    Ok(n) => Some(n),
                    Err(e) => {
                        self.error(&v.span(), e);
                        None
                    }
                }
            }
        };
        let clear = match &a.clear {
            None => Some((None, None)),
            Some(c) => match alert::parse_clear(c.get_ref(), metric) {
                Ok((cmps, n)) => Some((Some(cmps), n)),
                Err(e) => {
                    self.error(&c.span(), e);
                    None
                }
            },
        };
        let (condition, for_rounds, (clear, clear_rounds)) = (condition?, for_rounds?, clear?);
        Some(RuleKind::Threshold(Threshold {
            metric,
            condition,
            for_rounds,
            clear,
            clear_rounds: clear_rounds.unwrap_or(for_rounds),
        }))
    }

    /// Check an `alerts` setting's names against the rules, and mark them used.
    fn alert_refs(&mut self, v: Option<&Spanned<Vec<String>>>) -> Vec<String> {
        let Some(v) = v else {
            return Vec::new();
        };
        let mut out: Vec<String> = Vec::new();
        for name in v.get_ref() {
            match self.alert_names.get_mut(name) {
                Some(used) => {
                    *used = true;
                    if !out.contains(name) {
                        out.push(name.clone());
                    }
                }
                None => {
                    let msg = format!("unknown alert {name:?}; define it in an [[alert]] table");
                    self.error(&v.span(), msg);
                }
            }
        }
        out
    }

    fn server(&mut self, raw: RawServer) -> Option<ServerConfig> {
        let mut ok = true;
        // Blank is an error, but a real name keeps its spaces.
        let data_dir = raw.data_dir.get_ref().as_str();
        if data_dir.trim().is_empty() {
            self.error(&raw.data_dir.span(), "data_dir must not be empty");
            ok = false;
        } else if data_dir.contains('\0') {
            self.error(
                &raw.data_dir.span(),
                "data_dir must not contain a NUL character",
            );
            ok = false;
        }
        let vantage = match &raw.vantage {
            Some(v) if !valid_name(v.get_ref()) => {
                self.error(&v.span(), name_rule("vantage"));
                ok = false;
                String::new()
            }
            Some(v) => v.get_ref().clone(),
            None => DEFAULT_VANTAGE.to_string(),
        };
        let max_pps = match &raw.max_pps {
            Some(v) => match u32::try_from(*v.get_ref()) {
                Ok(n) if n >= 1 => n,
                _ => {
                    self.error(&v.span(), "max_pps must be a whole number of 1 or more");
                    ok = false;
                    0
                }
            },
            None => DEFAULT_MAX_PPS,
        };
        let listen_agents = match &raw.listen_agents {
            None => None,
            Some(v) if v.get_ref().trim() == "off" => None,
            Some(v) => match v.get_ref().trim().parse::<std::net::SocketAddr>() {
                Ok(a) => Some(a),
                Err(_) => {
                    self.error(
                        &v.span(),
                        "listen_agents must be an address and port such as \"0.0.0.0:4443\" \
                         or \"[::]:4443\", or \"off\"",
                    );
                    ok = false;
                    None
                }
            },
        };
        let listen_ui = match &raw.listen_ui {
            None => DEFAULT_LISTEN_UI.parse().ok(),
            Some(v) if v.get_ref().trim() == "off" => None,
            Some(v) => match v.get_ref().trim().parse::<std::net::SocketAddr>() {
                Ok(a) => {
                    if !a.ip().is_loopback() && raw.tls_cert.is_none() {
                        self.warning(
                            &v.span(),
                            format!(
                                "listen_ui {a} is reachable from other hosts without TLS: \
                                 pages, and passwords once users log in, cross the network \
                                 unencrypted (set tls_cert and tls_key)"
                            ),
                        );
                    }
                    Some(a)
                }
                Err(_) => {
                    self.error(
                        &v.span(),
                        "listen_ui must be an address and port such as \"127.0.0.1:8080\" \
                         or \"[::1]:8080\", or \"off\"",
                    );
                    ok = false;
                    None
                }
            },
        };
        let mut path = |v: &Spanned<String>, key: &str| -> Option<PathBuf> {
            let p = v.get_ref();
            if p.trim().is_empty() || p.contains('\0') {
                self.error(&v.span(), format!("{key} must be a file path"));
                ok = false;
                None
            } else {
                Some(PathBuf::from(p))
            }
        };
        let users_file = match &raw.users_file {
            Some(v) => path(v, "users_file"),
            None => Some(PathBuf::from(data_dir).join(DEFAULT_USERS_FILE)),
        };
        let tls = match (&raw.tls_cert, &raw.tls_key) {
            (None, None) => None,
            (Some(c), Some(k)) => match (path(c, "tls_cert"), path(k, "tls_key")) {
                (Some(cert), Some(key)) => Some(UiTls { cert, key }),
                _ => None,
            },
            (Some(v), None) | (None, Some(v)) => {
                self.error(&v.span(), "tls_cert and tls_key go together");
                ok = false;
                None
            }
        };
        if let (None, Some(v)) = (listen_ui, raw.tls_cert.as_ref()) {
            self.warning(&v.span(), "tls_cert is unused while listen_ui is \"off\"");
        }
        let anonymous = raw.anonymous.as_ref().is_some_and(|v| *v.get_ref());
        ok.then(|| ServerConfig {
            data_dir: PathBuf::from(data_dir),
            vantage,
            max_pps,
            listen_ui,
            users_file: users_file.unwrap_or_default(),
            anonymous,
            tls,
            listen_agents,
        })
    }

    fn target(
        &mut self,
        raw: &RawTarget,
        group: &str,
        s: &Settings,
        span: Range<usize>,
    ) -> Option<TargetConfig> {
        let errors_before = self.error_count();
        let name = raw.name.get_ref();
        if !valid_name(name) {
            self.error(&raw.name.span(), name_rule("target name"));
        }
        let kind = match raw.probe.as_ref().map(|p| (p, p.get_ref().as_str())) {
            None | Some((_, "icmp")) => "icmp",
            Some((_, "tcp")) => "tcp",
            Some((_, "dns")) => "dns",
            Some((_, "http" | "https")) => "http",
            Some((probe, p)) => {
                let msg = if p == "udp" {
                    format!("probe {p:?} is not available yet; {AVAILABLE}")
                } else {
                    format!("unknown probe {p:?}; {AVAILABLE}")
                };
                self.error(&probe.span(), msg);
                // Still check the target's own schedule values.
                self.check_layer(s);
                return None;
            }
        };
        for (key, value, applies) in [
            ("url", &raw.url, kind == "http"),
            ("expect_status", &raw.expect_status, kind == "http"),
            ("metric", &raw.metric, kind == "http"),
            ("method", &raw.method, kind == "http"),
            ("body_regex", &raw.body_regex, kind == "http"),
            ("tls_verify", &raw.tls_verify, kind == "http"),
            ("ca_file", &raw.ca_file, kind == "http"),
            ("sni", &raw.sni, kind == "http"),
            ("server", &raw.server, kind == "dns"),
            ("query", &raw.query, kind == "dns"),
            ("qtype", &raw.qtype, kind == "dns"),
            ("transport", &raw.transport, kind == "dns"),
            ("recursion", &raw.recursion, kind == "dns"),
            ("expect_rcode", &raw.expect_rcode, kind == "dns"),
            ("expect_answers", &raw.expect_answers, kind == "dns"),
            ("port", &raw.port, kind == "tcp" || kind == "dns"),
            ("mode", &raw.mode, kind == "tcp"),
        ] {
            if let (Some(v), false) = (value, applies) {
                self.error(&v.span(), format!("{key} does not apply to {kind} targets"));
            }
        }
        // Only the target's own `size`: a group or [defaults] size is a
        // shared ICMP default and may sit above TCP targets.
        if let (Some(v), false) = (&raw.size, kind == "icmp") {
            self.error(&v.span(), format!("size does not apply to {kind} targets"));
        }
        let probe = match kind {
            "tcp" => self.tcp(raw),
            "dns" => self.dns(raw),
            "http" => self.http(raw),
            _ => None,
        };
        // A DNS target's host is its server; an HTTP target's is in its URL.
        let (host_key, host_value) = if kind == "http" {
            if let Some(h) = &raw.host {
                self.error(&h.span(), "http targets take their host from url, not host");
            }
            let host = match &probe {
                Some(ProbeConfig::Http(h)) => raw
                    .url
                    .as_ref()
                    .map(|u| Spanned::new(u.span(), h.host.clone())),
                _ => None,
            };
            // Without a valid URL the error is already reported.
            if host.is_none() {
                self.check_layer(s);
                return None;
            }
            ("url host", host)
        } else if kind == "dns" {
            if let Some(h) = &raw.host {
                self.error(
                    &h.span(),
                    "dns targets name the server to query with server, not host",
                );
            }
            ("server", self.string_value("server", raw.server.as_ref()))
        } else {
            ("host", raw.host.clone())
        };
        // A host problem is recorded, but the settings are still checked.
        let host = match &host_value {
            Some(h) if !h.get_ref().trim().is_empty() => Some(h),
            Some(h) => {
                self.error(&h.span(), format!("{host_key} must not be empty"));
                None
            }
            None => {
                self.error(
                    &raw.name.span(),
                    format!("target {name:?} needs a {host_key}"),
                );
                None
            }
        };
        let literal: Option<IpAddr> = host.and_then(|h| h.get_ref().trim().parse().ok());
        if let (Some(h), None) = (host, literal) {
            if !valid_hostname(h.get_ref().trim()) {
                self.error(
                    &h.span(),
                    format!(
                        "{host_key} {:?} is neither an IP address nor a host name \
                         ({kind} targets take a bare name such as \"example.org\", not a URL)",
                        h.get_ref()
                    ),
                );
            }
        }

        let alerts = self.alert_refs(s.alerts.as_ref());
        let step = self.step(s.step.as_ref());
        let pings = self.pings(s.pings.as_ref());
        let timeout = self.timeout(s.timeout.as_ref());
        let size = self.size(s.size.as_ref());
        let family = self.family(s.family.as_ref(), literal, host);
        let spread = match (&s.spread, pings) {
            (Some(v), _) => self.duration("spread", v),
            (None, Some(p)) => Some(Duration::from_secs(u64::from(p))),
            (None, None) => None,
        };

        // The last sample is sent at spread × (pings − 1) / pings and must
        // get its full timeout before the next slot.
        let overrun = match (step, spread, timeout, pings) {
            (Some(step), Some(spread), Some(timeout), Some(pings)) => {
                let last = crate::round::RoundPlan {
                    count: pings,
                    spread,
                    timeout,
                    round_start: std::time::UNIX_EPOCH,
                }
                .sample_offset(pings.saturating_sub(1));
                last.checked_add(timeout)
                    .is_none_or(|end| end > step)
                    .then_some((step, last, timeout))
            }
            _ => None,
        };
        if let Some((step, last, timeout)) = overrun {
            let at = s.spread.as_ref().map_or(raw.name.span(), Spanned::span);
            self.error(
                &at,
                format!(
                    "target {name:?}: the last ping is sent {} into the round and its timeout ({}) \
                     ends after the next round starts (step {}); set a shorter spread or timeout \
                     or a longer step",
                    duration::format(last),
                    duration::format(timeout),
                    duration::format(step)
                ),
            );
        }
        if self.error_count() > errors_before {
            return None;
        }
        Some(TargetConfig {
            id: name.clone(),
            group: group.to_string(),
            host: host?.get_ref().trim().to_string(),
            family: family?,
            schedule: Schedule {
                step: step?,
                pings: pings?,
                spread: spread?,
                timeout: timeout?,
            },
            probe: match kind {
                "tcp" | "dns" | "http" => probe?,
                _ => ProbeConfig::Icmp {
                    payload_size: size?,
                },
            },
            alerts,
            parent: None,
            line: self.position(span.start).0,
        })
    }

    /// A string-valued probe key; any other TOML type is an error.
    fn string_value(
        &mut self,
        key: &str,
        v: Option<&Spanned<toml::Value>>,
    ) -> Option<Spanned<String>> {
        let v = v?;
        match v.get_ref().as_str() {
            Some(s) => Some(Spanned::new(v.span(), s.to_string())),
            None => {
                self.error(&v.span(), format!("{key} must be a string"));
                None
            }
        }
    }

    /// `port`: `default` when absent, else a whole number from 1 to 65535.
    /// `None` after an error, or when absent with no default (an error too).
    fn port(&mut self, raw: &RawTarget, default: Option<u16>, kind: &str) -> Option<u16> {
        match &raw.port {
            None if default.is_some() => default,
            None => {
                self.error(
                    &raw.name.span(),
                    format!("{kind} target {:?} needs a port", raw.name.get_ref()),
                );
                None
            }
            Some(v) => match v.get_ref().as_integer().map(u16::try_from) {
                Some(Ok(p)) if p >= 1 => Some(p),
                _ => {
                    self.error(&v.span(), "port must be a whole number from 1 to 65535");
                    None
                }
            },
        }
    }

    /// The HTTP settings of a target (§4.6).
    fn http(&mut self, raw: &RawTarget) -> Option<ProbeConfig> {
        let url = match self.string_value("url", raw.url.as_ref()) {
            None if raw.url.is_none() => {
                self.error(
                    &raw.name.span(),
                    format!("http target {:?} needs a url", raw.name.get_ref()),
                );
                None
            }
            None => None,
            Some(u) => match parse_http_url(u.get_ref().trim()) {
                Ok(parsed) => Some((u.get_ref().trim().to_string(), parsed)),
                Err(e) => {
                    self.error(&u.span(), format!("url {e}"));
                    None
                }
            },
        };
        let expect_status = match self.string_value("expect_status", raw.expect_status.as_ref()) {
            None if raw.expect_status.is_some() => None,
            None => Some(vec![(200, 299)]),
            Some(v) => match parse_status_ranges(v.get_ref()) {
                Ok(r) => Some(r),
                Err(e) => {
                    self.error(&v.span(), format!("expect_status: {e}"));
                    None
                }
            },
        };
        let metric = match self.string_value("metric", raw.metric.as_ref()) {
            None if raw.metric.is_some() => None,
            None => Some(HttpMetric::default()),
            Some(v) => match v.get_ref().as_str() {
                "ttfb" => Some(HttpMetric::Ttfb),
                "total" => Some(HttpMetric::Total),
                "connect" => Some(HttpMetric::Connect),
                "tls" => Some(HttpMetric::Tls),
                _ => {
                    self.error(
                        &v.span(),
                        "metric must be \"ttfb\", \"total\", \"connect\" or \"tls\"",
                    );
                    None
                }
            },
        };
        let method = match self.string_value("method", raw.method.as_ref()) {
            None if raw.method.is_some() => None,
            None => Some(HttpMethod::default()),
            Some(v) => match v.get_ref().to_ascii_uppercase().as_str() {
                "GET" => Some(HttpMethod::Get),
                "HEAD" => Some(HttpMethod::Head),
                _ => {
                    self.error(&v.span(), "method must be \"GET\" or \"HEAD\"");
                    None
                }
            },
        };
        let body_regex = match self.string_value("body_regex", raw.body_regex.as_ref()) {
            None if raw.body_regex.is_some() => None,
            None => Some(None),
            // Compiled (and checked) by the probe; rl-core has no regex engine.
            Some(v) if v.get_ref().is_empty() => {
                self.error(&v.span(), "body_regex must not be empty");
                None
            }
            Some(v) => Some(Some(v.get_ref().clone())),
        };
        let tls_verify = match &raw.tls_verify {
            None => Some(true),
            Some(v) => match v.get_ref().as_bool() {
                Some(b) => {
                    if !b {
                        self.warning(
                            &v.span(),
                            "tls_verify = false accepts any certificate, so this target \
                             cannot detect an impostor or an expired certificate",
                        );
                    }
                    Some(b)
                }
                None => {
                    self.error(&v.span(), "tls_verify must be true or false");
                    None
                }
            },
        };
        let ca_file = match self.string_value("ca_file", raw.ca_file.as_ref()) {
            None if raw.ca_file.is_some() => None,
            None => Some(None),
            Some(v) if v.get_ref().trim().is_empty() => {
                self.error(&v.span(), "ca_file must not be empty");
                None
            }
            Some(v) => Some(Some(PathBuf::from(v.get_ref()))),
        };
        let sni = match self.string_value("sni", raw.sni.as_ref()) {
            None if raw.sni.is_some() => None,
            None => Some(None),
            Some(v) if valid_hostname(v.get_ref()) => Some(Some(v.get_ref().clone())),
            Some(v) => {
                self.error(&v.span(), "sni must be a host name");
                None
            }
        };
        if let (Some((_, u)), Some(m)) = (&url, metric) {
            if m == HttpMetric::Tls && !u.tls {
                let at = raw.metric.as_ref().map_or(raw.name.span(), Spanned::span);
                self.error(&at, "metric \"tls\" needs an https url");
            }
        }
        let (url, u) = url?;
        Some(ProbeConfig::Http(HttpConfig {
            url,
            tls: u.tls,
            host: u.host,
            port: u.port,
            path: u.path,
            method: method?,
            expect_status: expect_status?,
            metric: metric?,
            body_regex: body_regex?,
            tls_verify: tls_verify?,
            ca_file: ca_file?,
            sni: sni?,
        }))
    }

    /// The DNS settings of a target (§4.5).
    fn dns(&mut self, raw: &RawTarget) -> Option<ProbeConfig> {
        let port = self.port(raw, Some(53), "dns");
        let query = match self.string_value("query", raw.query.as_ref()) {
            None if raw.query.is_none() => {
                self.error(
                    &raw.name.span(),
                    format!("dns target {:?} needs a query", raw.name.get_ref()),
                );
                None
            }
            None => None,
            Some(q) => {
                let name = q.get_ref().trim();
                // Check the name as it will be sent: {rand} becomes a
                // 12-character label, and "." (the root) is allowed.
                let sample = name.replace("{rand}", "r00000000000");
                if name == "." || valid_hostname(&sample) {
                    Some(name.to_string())
                } else {
                    self.error(
                        &q.span(),
                        format!(
                            "query {:?} is not a domain name (labels of letters, digits, '-' \
                             and '_', or {{rand}} for a random label)",
                            q.get_ref()
                        ),
                    );
                    None
                }
            }
        };
        let qtype = self.one_of("qtype", raw.qtype.as_ref(), DNS_QTYPES, "A");
        let expect_rcode = self.one_of(
            "expect_rcode",
            raw.expect_rcode.as_ref(),
            DNS_RCODES,
            "NOERROR",
        );
        let transport = match self.string_value("transport", raw.transport.as_ref()) {
            None if raw.transport.is_some() => None,
            None => Some(DnsTransport::default()),
            Some(t) => match t.get_ref().as_str() {
                "udp" => Some(DnsTransport::Udp),
                "tcp" => Some(DnsTransport::Tcp),
                _ => {
                    self.error(&t.span(), "transport must be \"udp\" or \"tcp\"");
                    None
                }
            },
        };
        let recursion = match &raw.recursion {
            None => Some(true),
            Some(v) => {
                let b = v.get_ref().as_bool();
                if b.is_none() {
                    self.error(&v.span(), "recursion must be true or false");
                }
                b
            }
        };
        let expect_answers = match &raw.expect_answers {
            None => Some(None),
            Some(v) => {
                let list: Option<Vec<String>> = v.get_ref().as_array().and_then(|a| {
                    a.iter()
                        .map(|x| x.as_str().map(|s| s.trim().to_string()))
                        .collect()
                });
                match list {
                    Some(l) if !l.is_empty() && l.iter().all(|s| !s.is_empty()) => Some(Some(l)),
                    _ => {
                        self.error(
                            &v.span(),
                            "expect_answers must be a non-empty list of strings, \
                             for example [\"192.0.2.1\"]",
                        );
                        None
                    }
                }
            }
        };
        // DS and DNSKEY answers are not decoded (hickory-proto is built
        // without its DNSSEC features), so they cannot be compared.
        if let (Some(t), Some(Some(_)), Some(v)) = (&qtype, &expect_answers, &raw.expect_answers) {
            if t == "DS" || t == "DNSKEY" {
                self.error(
                    &v.span(),
                    format!(
                        "expect_answers is not supported for {t} queries; check the rcode only"
                    ),
                );
                return None;
            }
        }
        Some(ProbeConfig::Dns(DnsConfig {
            port: port?,
            query: query?,
            qtype: qtype?,
            transport: transport?,
            recursion: recursion?,
            expect_rcode: expect_rcode?,
            expect_answers: expect_answers?,
        }))
    }

    /// A string key whose value must be one of `allowed` (case-insensitive),
    /// returned in upper case.
    fn one_of(
        &mut self,
        key: &str,
        v: Option<&Spanned<toml::Value>>,
        allowed: &[&str],
        default: &str,
    ) -> Option<String> {
        if v.is_none() {
            return Some(default.to_string());
        }
        let s = self.string_value(key, v)?;
        let up = s.get_ref().trim().to_ascii_uppercase();
        if allowed.contains(&up.as_str()) {
            Some(up)
        } else {
            self.error(
                &s.span(),
                format!(
                    "{key} {:?} is not one of {}",
                    s.get_ref(),
                    allowed.join(", ")
                ),
            );
            None
        }
    }

    /// The TCP settings of a target: `port` (required) and `mode`.
    fn tcp(&mut self, raw: &RawTarget) -> Option<ProbeConfig> {
        let port = self.port(raw, None, "tcp");
        let mode = match &raw.mode {
            None => Some(TcpMode::default()),
            Some(v) => match v.get_ref().as_str() {
                Some("connect") => Some(TcpMode::Connect),
                Some("banner") => Some(TcpMode::Banner),
                _ => {
                    self.error(&v.span(), "mode must be \"connect\" or \"banner\"");
                    None
                }
            },
        };
        Some(ProbeConfig::Tcp {
            port: port?,
            mode: mode?,
        })
    }

    /// Check the values a `[defaults]` or group table declares itself, so
    /// a bad value is reported even when every target overrides it.
    /// Cross-field checks need the resolved schedule and run per target.
    fn check_layer(&mut self, s: &Settings) {
        self.step(s.step.as_ref());
        self.pings(s.pings.as_ref());
        self.timeout(s.timeout.as_ref());
        self.size(s.size.as_ref());
        self.family(s.family.as_ref(), None, None);
        if let Some(v) = &s.spread {
            self.duration("spread", v);
        }
        // Names are checked where they are written, so a typo in
        // [defaults] is reported even if every target overrides it.
        if let Some(v) = &s.alerts {
            for name in v.get_ref() {
                if !self.alert_names.contains_key(name) {
                    let msg = format!("unknown alert {name:?}; define it in an [[alert]] table");
                    self.error(&v.span(), msg);
                }
            }
        }
    }

    fn error_count(&self) -> usize {
        self.errors
    }

    fn duration(&mut self, key: &str, v: &Spanned<String>) -> Option<Duration> {
        match duration::parse(v.get_ref()) {
            Ok(d) => Some(d),
            Err(e) => {
                self.error(&v.span(), format!("{key}: {e}"));
                None
            }
        }
    }

    fn step(&mut self, v: Option<&Spanned<String>>) -> Option<Duration> {
        let Some(v) = v else {
            return Some(DEFAULT_STEP);
        };
        let d = self.duration("step", v)?;
        let whole = d.subsec_nanos() == 0;
        let secs = d.as_secs();
        if !whole || secs == 0 || DAY_SECS % secs != 0 {
            self.error(
                &v.span(),
                "step must be whole seconds that divide a day evenly (for example 60s, 300s, 1h), \
                 so rounds line up across agents and days",
            );
            return None;
        }
        Some(d)
    }

    fn pings(&mut self, v: Option<&Spanned<i64>>) -> Option<u16> {
        let Some(v) = v else {
            return Some(DEFAULT_PINGS);
        };
        match *v.get_ref() {
            n @ 1..=MAX_PINGS => u16::try_from(n).ok(),
            _ => {
                self.error(
                    &v.span(),
                    format!("pings must be between 1 and {MAX_PINGS}"),
                );
                None
            }
        }
    }

    fn timeout(&mut self, v: Option<&Spanned<String>>) -> Option<Duration> {
        let Some(v) = v else {
            return Some(DEFAULT_TIMEOUT);
        };
        let d = self.duration("timeout", v)?;
        if d.is_zero() || d > MAX_TIMEOUT {
            self.error(&v.span(), "timeout must be more than 0 and at most 60s");
            return None;
        }
        Some(d)
    }

    fn size(&mut self, v: Option<&Spanned<i64>>) -> Option<u16> {
        let Some(v) = v else {
            return Some(DEFAULT_SIZE);
        };
        match *v.get_ref() {
            n @ MIN_SIZE..=MAX_SIZE => u16::try_from(n).ok(),
            _ => {
                self.error(
                    &v.span(),
                    format!("size must be between {MIN_SIZE} and {MAX_SIZE} bytes"),
                );
                None
            }
        }
    }

    fn family(
        &mut self,
        v: Option<&Spanned<String>>,
        literal: Option<IpAddr>,
        host: Option<&Spanned<String>>,
    ) -> Option<Family> {
        let lit_family = literal.map(|a| if a.is_ipv6() { Family::V6 } else { Family::V4 });
        let Some(v) = v else {
            return Some(lit_family.unwrap_or(Family::V4));
        };
        let family = match v.get_ref().as_str() {
            "v4" => Family::V4,
            "v6" => Family::V6,
            "both" => Family::Both,
            "prefer-v6" => Family::PreferV6,
            other => {
                self.error(
                    &v.span(),
                    format!(
                        "family {other:?} is not one of \"v4\", \"v6\", \"both\", \"prefer-v6\""
                    ),
                );
                return None;
            }
        };
        match (lit_family, host) {
            // prefer-v6 simply uses the literal's family.
            (Some(lf), Some(host)) if family != lf && family != Family::PreferV6 => {
                self.error(
                    &host.span(),
                    format!(
                        "host {:?} is an {} address but family is {:?}",
                        host.get_ref(),
                        if lf == Family::V6 { "IPv6" } else { "IPv4" },
                        family.as_str()
                    ),
                );
                None
            }
            _ => Some(family),
        }
    }
}

fn valid_name(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= MAX_NAME_LEN
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// A DNS name: dot-separated labels of letters, digits, '-' and '_'
/// (1 to 63 characters, not starting or ending with '-'), at most 253
/// characters, with an optional final dot.
fn valid_hostname(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// A name (not an address) whose last label is all digits, which TLS
/// rejects as a server name.
fn numeric_tld(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_err()
        && host
            .trim_end_matches('.')
            .rsplit('.')
            .next()
            .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// `localhost` or a loopback address: traffic to it stays on this machine.
fn loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback())
}

/// `local@domain` or `Display Name <local@domain>`. Only the shape is
/// checked here; the mail library parses it fully at start.
fn check_mailbox(s: &str) -> Result<(), String> {
    let addr = match (s.rfind('<'), s.strip_suffix('>')) {
        (Some(i), Some(_)) => &s[i + 1..s.len() - 1],
        (None, None) => s.trim(),
        _ => return Err(format!("{s:?} has an unmatched '<' or '>'")),
    };
    let ok = s.chars().all(|c| !c.is_control())
        && addr.split_once('@').is_some_and(|(l, d)| {
            !l.is_empty()
                && !d.is_empty()
                && !d.contains('@')
                && !addr.contains(|c: char| c.is_whitespace() || c == '<' || c == '>')
        });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{s:?} is not an e-mail address like name@example.net"
        ))
    }
}

/// `host`, `host:port`, `[v6]:port` or a bare IPv6 address.
fn split_address(s: &str, default_port: u16) -> Result<(String, u16), String> {
    let s = s.trim();
    let port = |p: &str| match p.parse::<u16>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(format!("port {p:?} is not 1 to 65535")),
    };
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .ok_or_else(|| "missing ']' after the IPv6 address".to_string())?;
        match after {
            "" => (h, default_port),
            _ => match after.strip_prefix(':') {
                Some(p) => (h, port(p)?),
                None => return Err(format!("unexpected {after:?} after ']'")),
            },
        }
    } else if s.parse::<std::net::Ipv6Addr>().is_ok() {
        (s, default_port)
    } else {
        match s.rsplit_once(':') {
            Some((h, _)) if h.contains(':') => {
                return Err(
                    "put an IPv6 address with a port in brackets, as in [2001:db8::1]:514".into(),
                );
            }
            Some((h, p)) => (h, port(p)?),
            None => (s, default_port),
        }
    };
    if host.parse::<std::net::IpAddr>().is_err() && !valid_hostname(host) {
        return Err(format!("{host:?} is not a host name or address"));
    }
    if s.starts_with('[') && host.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(format!("{host:?} in brackets is not an IPv6 address"));
    }
    Ok((host.to_string(), port))
}

fn name_rule(what: &str) -> String {
    format!(
        "{what} must be 1 to {MAX_NAME_LEN} characters of letters, digits, '.', '_' or '-', \
         starting with a letter or digit"
    )
}

fn line_starts(src: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(src.match_indices('\n').map(|(i, _)| i + 1))
        .collect()
}

/// Control characters (from quoted keys or values) escaped, line breaks
/// included, so a message stays on one line and cannot rewrite the terminal
/// it is printed on or forge another diagnostic.
fn escape_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[server]
data_dir = "/tmp/rl"

[[group]]
name = "Core"

  [[group.target]]
  name = "core-fw"
  host = "10.0.0.1"
"#;

    fn errors(src: &str) -> Vec<String> {
        parse(src)
            .diagnostics
            .into_iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.to_string())
            .collect()
    }

    const ALERTS: &str = r#"
[server]
data_dir = "/tmp/rl"

[defaults]
alerts = ["loss-burst"]

[[alert]]
name    = "loss-burst"
type    = "loss"
pattern = [">0%", "*3*", ">0%"]

[[alert]]
name      = "slow"
metric    = "median"
condition = "> 20ms"
for       = "3 rounds"
clear     = "< 15ms"

[[group]]
name = "Core"

  [[group.target]]
  name = "a"
  host = "10.0.0.1"

  [[group.target]]
  name   = "b"
  host   = "10.0.0.2"
  alerts = ["loss-burst", "slow"]
"#;

    const DEPENDENCIES: &str = r#"
[server]
data_dir = "/tmp/rl"

[[alert]]
name      = "slow"
metric    = "median"
condition = "> baseline_p50_7d * 2 + 5ms"

[[silence]]
name     = "sunday"
groups   = ["Branch"]
rrule    = "FREQ=WEEKLY;BYDAY=SU;BYHOUR=2"
duration = "2h"
comment  = "ISP maintenance"

[[silence]]
name    = "works"
targets = ["gw"]
alerts  = ["slow"]
start   = "2026-12-01T22:00:00Z"
end     = "2026-12-02T04:00:00+01:00"

[[group]]
name   = "Core"
alerts = ["slow"]

  [[group.target]]
  name = "gw"
  host = "10.0.0.1"

[[group]]
name   = "Branch"
parent = "router"

  [[group.target]]
  name   = "router"
  host   = "10.1.0.1"
  parent = "gw"

  [[group.target]]
  name = "printer"
  host = "10.1.0.9"
"#;

    const OUTPUTS: &str = r#"
[server]
data_dir = "/tmp/rl"

[[alert]]
name      = "loss"
metric    = "loss"
condition = "> 10%"

[[output]]
name      = "siem"
type      = "syslog"
address   = "siem.example.net"
transport = "tls"
ca_file   = "/etc/routelith/siem-ca.pem"
facility  = "local3"
events    = ["alert_raised", "alert_cleared"]
groups    = ["Core"]

[[output]]
name    = "udp"
type    = "syslog"
address = "[2001:db8::5]:5514"
format  = "rfc3164"
alerts  = ["loss"]
quiet   = true

[[output]]
name  = "archive"
type  = "jsonl"
path  = "/var/log/routelith/events.jsonl"
queue = 50

[[group]]
name   = "Core"
alerts = ["loss"]

  [[group.target]]
  name = "gw"
  host = "10.0.0.1"
"#;

    #[test]
    fn outputs_parse() {
        use crate::output::{Framing, OutputKind, SyslogFormat, Transport};
        let p = parse(OUTPUTS);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let c = p.config.unwrap();
        assert_eq!(c.outputs.len(), 3);
        let OutputKind::Syslog(s) = &c.outputs[0].kind else {
            panic!("{:?}", c.outputs[0]);
        };
        assert_eq!((s.host.as_str(), s.port), ("siem.example.net", 6514));
        assert_eq!(s.transport, Transport::Tls);
        assert_eq!(s.format, SyslogFormat::Rfc5424);
        assert_eq!(s.framing, Framing::OctetCounting);
        assert_eq!(s.facility, 19);
        assert_eq!(s.app_name, "routelith");
        assert_eq!(c.outputs[0].filter.groups, ["Core"]);
        assert_eq!(c.outputs[0].filter.events.len(), 2);
        assert!(!c.outputs[0].filter.quiet);
        assert_eq!(c.outputs[0].queue, crate::output::DEFAULT_QUEUE);
        let OutputKind::Syslog(s) = &c.outputs[1].kind else {
            panic!("{:?}", c.outputs[1]);
        };
        assert_eq!((s.host.as_str(), s.port), ("2001:db8::5", 5514));
        assert_eq!(
            (s.transport, s.format),
            (Transport::Udp, SyslogFormat::Rfc3164)
        );
        assert_eq!(s.facility, 16);
        assert!(c.outputs[1].filter.quiet);
        assert!(matches!(&c.outputs[2].kind, OutputKind::Jsonl(j)
            if j.path == std::path::Path::new("/var/log/routelith/events.jsonl")));
        assert_eq!(c.outputs[2].queue, 50);
    }

    #[test]
    fn eventlog_outputs_are_for_windows() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[output]]
name = "events"
type = "eventlog"
events = ["alert_raised"]
[[output]]
name = "wrong"
type = "eventlog"
path = "x.jsonl"
[[group]]
name = "G"
  [[group.target]]
  name = "t"
  host = "10.0.0.1"
"#;
        let e = errors(src);
        if cfg!(windows) {
            assert_eq!(e.len(), 1, "{e:?}");
            assert!(
                e[0].contains("path applies to type = \"jsonl\" only"),
                "{e:?}"
            );
            let ok = src
                .split("[[output]]\nname = \"wrong\"")
                .next()
                .unwrap()
                .to_string()
                + "[[group]]\nname = \"G\"\n  [[group.target]]\n  name = \"t\"\n  host = \"10.0.0.1\"\n";
            let c = parse(&ok).config.unwrap();
            assert_eq!(c.outputs[0].kind, crate::output::OutputKind::EventLog);
            assert_eq!(c.outputs[0].filter.events, ["alert_raised"]);
        } else {
            assert_eq!(e.len(), 3, "{e:?}");
            assert!(e[0].contains("exists only on Windows"), "{e:?}");
        }
    }

    #[test]
    fn output_mistakes_are_reported() {
        for (from, to, message) in [
            (
                "name    = \"udp\"",
                "name    = \"siem\"",
                "duplicate output name",
            ),
            (
                "type  = \"jsonl\"",
                "type  = \"email\"",
                "needs the address of the SMTP server",
            ),
            (
                "type  = \"jsonl\"",
                "type  = \"carrier-pigeon\"",
                "unknown output type",
            ),
            (
                "transport = \"tls\"",
                "transport = \"sctp\"",
                "transport \"sctp\"",
            ),
            (
                "transport = \"tls\"",
                "",
                "ca_file applies to transport = \"tls\" only",
            ),
            (
                "format  = \"rfc3164\"",
                "format = \"rfc5425\"",
                "format \"rfc5425\"",
            ),
            (
                "facility  = \"local3\"",
                "facility = \"local9\"",
                "unknown facility",
            ),
            (
                "[\"alert_raised\",",
                "[\"alert_rased\",",
                "unknown event kind",
            ),
            (
                "groups    = [\"Core\"]",
                "groups = [\"Edge\"]",
                "unknown group \"Edge\"",
            ),
            (
                "alerts  = [\"loss\"]",
                "alerts = [\"lost\"]",
                "unknown alert \"lost\"",
            ),
            (
                "address = \"[2001:db8::5]:5514\"",
                "address = \"[2001:db8::5]:0\"",
                "port \"0\"",
            ),
            (
                "address = \"[2001:db8::5]:5514\"",
                "address = \"bad host:514\"",
                "not a host name",
            ),
            ("address = \"[2001:db8::5]:5514\"", "", "needs an address"),
            ("queue = 50", "queue = 0", "queue must be from 1"),
            (
                "path  = \"/var",
                "address = \"x\"\npath  = \"/var",
                "address applies to type = \"syslog\" or \"email\" only",
            ),
            (
                "path  = \"/var/log/routelith/events.jsonl\"",
                "",
                "needs a path",
            ),
            (
                "quiet   = true",
                "quiet = true\nframing = \"lf\"",
                "framing applies to transport",
            ),
            (
                "quiet   = true",
                "quiet = true\napp_name = \"route lith\"",
                "app_name must be",
            ),
            (
                "ca_file   = \"/etc/routelith/siem-ca.pem\"",
                "cert_file = \"/c.pem\"",
                "cert_file needs a key_file",
            ),
            (
                "address = \"[2001:db8::5]:5514\"",
                "address = \"2001:db8::5:65535\"",
                "in brackets",
            ),
            (
                "\"siem.example.net\"",
                "\"collector.123\"",
                "set server_name",
            ),
            (
                "quiet   = true",
                "quiet = true\napp_name = \"route-lith\"",
                "letters or digits",
            ),
            (
                "quiet   = true",
                "quiet = true\nsd_id = \"routelith\"",
                "name@enterprise-number",
            ),
            (
                "queue = 50",
                "queue = 50\n[[output]]\nname = \"again\"\ntype = \"jsonl\"\npath = \"/var/log/routelith/events.jsonl\"",
                "already writes this file",
            ),
        ] {
            assert!(OUTPUTS.contains(from), "{from}");
            let src = OUTPUTS.replacen(from, to, 1);
            let errs = errors(&src);
            assert!(
                errs.iter().any(|e| e.contains(message)),
                "{message}: {errs:?}"
            );
        }
    }

    const WEBHOOKS: &str = r#"
[server]
data_dir = "/tmp/rl"

[[output]]
name   = "ops"
type   = "webhook"
url    = "https://hooks.example.net:8443/routelith?x=1"
secret = "s3cr3t-${env:RL_TEST_SURELY_UNSET_SUFFIX}"
ca_file = "/etc/routelith/hooks-ca.pem"

[[output]]
name   = "phone"
type   = "webhook"
format = "ntfy"
url    = "https://ntfy.lan/alerts"
token  = "tk_abc"

[[output]]
name   = "chat"
type   = "webhook"
format = "slack"
url    = "https://hooks.slack.example/services/T0/B0/XYZ"
"#;

    #[test]
    fn webhooks_parse() {
        use crate::output::{OutputKind, WebhookFormat};
        let src = WEBHOOKS.replace("-${env:RL_TEST_SURELY_UNSET_SUFFIX}", "");
        let p = parse(&src);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let c = p.config.unwrap();
        assert_eq!(c.outputs.len(), 3);
        let OutputKind::Webhook(w) = &c.outputs[0].kind else {
            panic!("{:?}", c.outputs[0]);
        };
        assert_eq!(w.format, WebhookFormat::Json);
        assert!(w.url.tls);
        assert_eq!(
            (w.url.host.as_str(), w.url.port),
            ("hooks.example.net", 8443)
        );
        assert_eq!(w.url.path, "/routelith?x=1");
        assert_eq!(w.secret.as_ref().unwrap().expose(), "s3cr3t");
        assert!(w.ca_file.is_some());
        // Neither the secret nor the URL path shows up in Debug output.
        let shown = format!("{:?}", c.outputs[0]);
        assert!(
            !shown.contains("s3cr3t") && !shown.contains("routelith?x"),
            "{shown}"
        );
        let OutputKind::Webhook(w) = &c.outputs[1].kind else {
            panic!("{:?}", c.outputs[1]);
        };
        assert_eq!(w.format, WebhookFormat::Ntfy);
        assert!(w.url.tls);
        assert_eq!(w.url.port, 443);
        assert_eq!(w.token.as_ref().unwrap().expose(), "tk_abc");
        let OutputKind::Webhook(w) = &c.outputs[2].kind else {
            panic!("{:?}", c.outputs[2]);
        };
        assert_eq!(w.format, WebhookFormat::Slack);
        assert_eq!(c.outputs[2].kind.type_name(), "webhook");
    }

    #[test]
    fn webhook_mistakes_are_reported() {
        let ok = WEBHOOKS.replace("-${env:RL_TEST_SURELY_UNSET_SUFFIX}", "");
        for (src, message, hidden) in [
            (
                WEBHOOKS.to_string(),
                "environment variable RL_TEST_SURELY_UNSET_SUFFIX is not set",
                "",
            ),
            (
                ok.replace("url    = \"https://ntfy.lan/alerts\"\n", ""),
                "needs the url",
                "",
            ),
            (
                ok.replace("https://ntfy.lan/alerts", "ftp://ntfy.lan/alerts-k3y"),
                "output \"phone\": url",
                "alerts-k3y",
            ),
            (
                ok.replace("https://ntfy.lan/alerts", "http://ntfy.lan/alerts"),
                "token needs an https:// url",
                "",
            ),
            (
                ok.replace("format = \"ntfy\"", "format = \"pager\""),
                "format \"pager\" is not one of",
                "",
            ),
            (
                ok.replace("format = \"ntfy\"", "format = \"slack\""),
                "token applies to format",
                "",
            ),
            (
                ok.replace("format = \"slack\"", "format = \"teams\"\nsecret = \"x\""),
                "secret applies to format = \"json\" only",
                "",
            ),
            (ok.replace("\"s3cr3t\"", "\"\""), "secret is empty", ""),
            (
                ok.replace("\"tk_abc\"", "\"tk abc\u{e9}\""),
                "printable ASCII",
                "tk abc",
            ),
            (
                ok.replace(
                    "format = \"slack\"",
                    "format = \"slack\"\nca_file = \"/ca.pem\"",
                )
                .replace("https://hooks.slack.example", "http://hooks.slack.example"),
                "ca_file applies to an https:// url only",
                "",
            ),
            (
                ok.replace("format = \"ntfy\"", "format = \"ntfy\"\naddress = \"x\""),
                "address applies to type = \"syslog\" or \"email\" only",
                "",
            ),
            (
                ok.replace("format = \"ntfy\"", "format = \"ntfy\"\npath = \"/x\""),
                "path applies to type = \"jsonl\" only",
                "",
            ),
            (
                ok.replace(
                    "secret = \"s3cr3t\"",
                    "secret = \"${file:/nonexistent/routelith-secret}\"",
                ),
                "cannot read /nonexistent/routelith-secret",
                "",
            ),
        ] {
            let errs = errors(&src);
            assert!(
                errs.iter().any(|e| e.contains(message)),
                "{message}: {errs:?}"
            );
            if !hidden.is_empty() {
                assert!(errs.iter().all(|e| !e.contains(hidden)), "{errs:?}");
            }
        }
        // A URL built from a reference: the parser's complaint would quote
        // the value, so it is not repeated.
        let path = std::env::var("PATH").unwrap();
        let errs = errors(&ok.replace("https://ntfy.lan/alerts", "https://ntfy.lan:${env:PATH}"));
        assert!(
            errs.iter()
                .any(|e| e.contains("once its references are filled in")),
            "{errs:?}"
        );
        assert!(errs.iter().all(|e| !e.contains(&path)), "{errs:?}");
        // A token may go in clear to a receiver on this machine.
        for host in ["localhost:8080", "127.0.0.1", "[::1]"] {
            let src = ok.replace("https://ntfy.lan/alerts", &format!("http://{host}/alerts"));
            assert!(errors(&src).is_empty(), "{host}: {:?}", errors(&src));
        }
    }
    const EMAILS: &str = r#"
[server]
data_dir = "/tmp/rl"

[[output]]
name     = "noc"
type     = "email"
address  = "smtp.example.net"
username = "routelith"
password = "${file:/nonexistent/routelith-smtp}"
from     = "Routelith <routelith@example.net>"
to       = ["noc@example.net", "On call <oncall@example.net>"]
graph    = "6h"

[[output]]
name     = "relay"
type     = "email"
address  = "[::1]:2525"
security = "none"
from     = "routelith@example.net"
to       = ["ops@example.net"]
graph    = "off"
"#;

    #[test]
    fn emails_parse() {
        use crate::output::{OutputKind, SmtpSecurity};
        // No password file here, so the first output logs in without one
        // for this test.
        let src = EMAILS
            .replace("username = \"routelith\"\n", "")
            .replace("password = \"${file:/nonexistent/routelith-smtp}\"\n", "");
        let p = parse(&src);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let c = p.config.unwrap();
        let OutputKind::Email(e) = &c.outputs[0].kind else {
            panic!("{:?}", c.outputs[0]);
        };
        assert_eq!((e.host.as_str(), e.port), ("smtp.example.net", 587));
        assert_eq!(e.security, SmtpSecurity::StartTls);
        assert_eq!(e.to.len(), 2);
        assert_eq!(e.graph, Some(Duration::from_secs(6 * 3600)));
        assert_eq!(c.outputs[0].kind.type_name(), "email");
        let OutputKind::Email(e) = &c.outputs[1].kind else {
            panic!("{:?}", c.outputs[1]);
        };
        assert_eq!((e.host.as_str(), e.port), ("::1", 2525));
        assert_eq!(e.security, SmtpSecurity::None);
        assert_eq!(e.graph, None);
        // security = "tls" defaults to port 465.
        let p = parse(&src.replace(
            "address  = \"smtp.example.net\"",
            "address = \"smtp.example.net\"\nsecurity = \"tls\"",
        ));
        let OutputKind::Email(e) = &p.config.unwrap().outputs[0].kind else {
            panic!();
        };
        assert_eq!(e.port, 465);
    }

    #[test]
    fn a_password_comes_from_a_reference() {
        use crate::output::OutputKind;
        let dir = std::env::temp_dir().join(format!("rl-core-pw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("smtp");
        std::fs::write(&file, "hunter2\n").unwrap();
        // Forward slashes: a Windows path's backslashes would be escapes in
        // a TOML string, and Windows takes either.
        let path = file.to_str().unwrap().replace('\\', "/");
        let src = EMAILS.replace("/nonexistent/routelith-smtp", &path);
        let p = parse(&src);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let c = p.config.unwrap();
        let OutputKind::Email(e) = &c.outputs[0].kind else {
            panic!();
        };
        assert_eq!(e.password.as_ref().unwrap().expose(), "hunter2");
        assert_eq!(e.username.as_deref(), Some("routelith"));
        assert!(!format!("{:?}", c.outputs[0]).contains("hunter2"));
    }

    #[test]
    fn email_mistakes_are_reported() {
        for (from, to, message) in [
            (
                "password = \"${file:/nonexistent/routelith-smtp}\"",
                "password = \"hunter2\"",
                "password must come from ${env:NAME} or ${file:/path}",
            ),
            (
                "password = \"${file:/nonexistent/routelith-smtp}\"\n",
                "",
                "username needs a password",
            ),
            (
                "username = \"routelith\"\n",
                "",
                "password needs a username",
            ),
            (
                "${file:/nonexistent/routelith-smtp}",
                "${file:/nonexistent/routelith-smtp}",
                "cannot read /nonexistent/routelith-smtp",
            ),
            (
                "address  = \"smtp.example.net\"",
                "address = \"smtp.example.net\"\nsecurity = \"none\"",
                "a password needs security = \"starttls\" or \"tls\"",
            ),
            (
                "security = \"none\"",
                "security = \"ssl\"",
                "security \"ssl\" is not",
            ),
            (
                "security = \"none\"",
                "security = \"none\"\nca_file = \"/ca.pem\"",
                "ca_file applies to security",
            ),
            (
                "address  = \"[::1]:2525\"\n",
                "",
                "needs the address of the SMTP server",
            ),
            (
                "from     = \"routelith@example.net\"\n",
                "",
                "needs a from address",
            ),
            (
                "from     = \"routelith@example.net\"",
                "from = \"routelith\"",
                "from \"routelith\" is not an e-mail address",
            ),
            (
                "[\"ops@example.net\"]",
                "[\"ops@example.net\", \"Ops <ops@example.net\"]",
                "unmatched",
            ),
            ("[\"ops@example.net\"]", "[]", "to is empty"),
            (
                "graph    = \"6h\"",
                "graph = \"1m\"",
                "graph must be from 10m to 30d",
            ),
            (
                "graph    = \"off\"",
                "graph = \"off\"\nurl = \"https://x/\"",
                "url applies to type = \"webhook\" only",
            ),
            (
                "graph    = \"off\"",
                "graph = \"off\"\npath = \"/x\"",
                "path applies to type = \"jsonl\" only",
            ),
        ] {
            assert!(EMAILS.contains(from), "{from}");
            let src = EMAILS.replacen(from, to, 1);
            let errs = errors(&src);
            assert!(
                errs.iter().any(|e| e.contains(message)),
                "{message}: {errs:?}"
            );
        }
        // Keys of other types are named with the types they belong to.
        let errs = errors(&EMAILS.replace(
            "graph    = \"off\"",
            "graph = \"off\"\nfacility = \"local0\"",
        ));
        assert!(
            errs.iter()
                .any(|e| e.contains("facility applies to type = \"syslog\" only")),
            "{errs:?}"
        );
        // A loopback server may take a password in clear.
        let local = EMAILS.replace(
            "address  = \"smtp.example.net\"",
            "address = \"127.0.0.1:2525\"\nsecurity = \"none\"",
        );
        assert!(
            errors(&local).iter().all(|e| !e.contains("in clear")),
            "{:?}",
            errors(&local)
        );
    }

    #[test]
    fn slas_parse_and_mistakes_are_reported() {
        let src = format!(
            "{MINIMAL}\n[[sla]]\nname = \"core\"\ngroups = [\"Core\"]\navailability = \"99.9%\"\n\
             loss = \"0.5 %\"\nlatency = \"20ms\"\npercentile = 90\n\n\
             [[sla]]\nname = \"all\"\navailability = \"99%\"\n"
        );
        let p = parse(&src);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let c = p.config.unwrap();
        assert_eq!(c.slas.len(), 2);
        let s = &c.slas[0];
        assert_eq!(
            (s.availability, s.loss, s.latency_us, s.percentile),
            (Some(99.9), Some(0.5), Some(20_000), 90)
        );
        assert!(s.covers("core-fw", "Core") && !s.covers("x", "Other"));
        assert_eq!((c.slas[1].percentile, c.slas[1].latency_us), (95, None));
        assert!(c.slas[1].covers("anything", "Other"));

        for (sla, message) in [
            ("name = \"x\"\n", "needs availability, loss or latency"),
            (
                "name = \"x\"\navailability = \"99.9\"\n",
                "must be a percentage",
            ),
            ("name = \"x\"\nloss = \"101%\"\n", "must be a percentage"),
            (
                "name = \"x\"\nlatency = \"0ms\"\n",
                "latency must be above 0",
            ),
            (
                "name = \"x\"\nlatency = \"5ms\"\npercentile = 100\n",
                "percentile must be 50 to 99",
            ),
            (
                "name = \"x\"\nloss = \"1%\"\npercentile = 90\n",
                "percentile applies with latency only",
            ),
            (
                "name = \"x\"\nloss = \"1%\"\ntargets = [\"nope\"]\n",
                "unknown target \"nope\"",
            ),
            (
                "name = \"x\"\nloss = \"1%\"\n\n[[sla]]\nname = \"x\"\nloss = \"1%\"\n",
                "duplicate sla name",
            ),
        ] {
            let errs = errors(&format!("{MINIMAL}\n[[sla]]\n{sla}"));
            assert!(
                errs.iter().any(|e| e.contains(message)),
                "{message}: {errs:?}"
            );
        }
    }

    #[test]
    fn parents_and_silences_parse() {
        use crate::silence::When;
        let p = parse(DEPENDENCIES);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let c = p.config.unwrap();
        let parent = |id: &str| {
            c.targets
                .iter()
                .find(|t| t.id == id)
                .and_then(|t| t.parent.clone())
        };
        assert_eq!(parent("gw"), None);
        // The target's own setting, and the group's for the others.
        assert_eq!(parent("router").as_deref(), Some("gw"));
        assert_eq!(parent("printer").as_deref(), Some("router"));
        assert_eq!(c.silences.len(), 2);
        assert_eq!(c.silences[0].groups, ["Branch"]);
        assert!(matches!(
            c.silences[0].when,
            When::Every {
                duration_ms: 7_200_000,
                ..
            }
        ));
        assert_eq!(
            c.silences[1].when,
            When::Once {
                start_ms: 1_796_162_400_000,
                end_ms: 1_796_180_400_000
            }
        );
        assert_eq!(c.silences[1].alerts, ["slow"]);
    }

    #[test]
    fn parent_and_silence_mistakes_are_reported() {
        for (from, to, message) in [
            (
                "parent = \"gw\"",
                "parent = \"nope\"",
                "parent \"nope\" of target \"router\" is not a target",
            ),
            (
                "parent = \"gw\"",
                "parent = \"router\"",
                "cannot be its own parent",
            ),
            (
                "name = \"gw\"\n",
                "name = \"gw\"\n  parent = \"printer\"\n",
                "form a loop",
            ),
            (
                "groups   = [\"Branch\"]",
                "groups   = [\"Nope\"]",
                "unknown group \"Nope\"",
            ),
            (
                "targets = [\"gw\"]",
                "targets = [\"nope\"]",
                "unknown target \"nope\"",
            ),
            (
                "alerts  = [\"slow\"]",
                "alerts  = [\"fast\"]",
                "unknown alert \"fast\"",
            ),
            ("BYHOUR=2", "BYHOUR=25", "BYHOUR"),
            (
                "FREQ=WEEKLY",
                "FREQ=MONTHLY",
                "FREQ=MONTHLY is not supported",
            ),
            (
                "duration = \"2h\"",
                "duration = \"169h\"",
                "from 1m to 168h",
            ),
            ("duration = \"2h\"", "", "needs a duration"),
            ("+01:00", "", "is not a time with a zone"),
            (
                "end     = \"2026-12-02T04:00:00+01:00\"",
                "end = \"2026-12-01T21:00:00Z\"",
                "end must be after start",
            ),
            (
                "end     = \"2026-12-02T04:00:00+01:00\"",
                "",
                "needs a start and an end",
            ),
            (
                "name    = \"works\"",
                "name    = \"sunday\"",
                "duplicate silence name",
            ),
            ("* 2 + 5ms", "* 2 + 5", "needs a time unit"),
        ] {
            assert!(DEPENDENCIES.contains(from), "{from}");
            let src = DEPENDENCIES.replacen(from, to, 1);
            let errs = errors(&src);
            assert!(
                errs.iter().any(|e| e.contains(message)),
                "{message}: {errs:?}"
            );
        }
        // A parent that is not measured here only warns.
        let src = DEPENDENCIES.replace(
            "name   = \"Core\"\n",
            "name   = \"Core\"\nvantages = [\"elsewhere\"]\n",
        );
        let p = parse(&src);
        assert!(errors(&src).is_empty(), "{:?}", p.diagnostics);
        assert!(
            p.diagnostics
                .iter()
                .any(|d| d.message.contains("never suppresses")),
            "{:?}",
            p.diagnostics
        );
    }

    #[test]
    fn alert_rules_parse_and_cascade() {
        use crate::alert::{Op, PatternItem};
        let p = parse(ALERTS);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let c = p.config.unwrap();
        assert_eq!(c.alerts.len(), 2);
        assert_eq!(c.alerts[0].name, "loss-burst");
        assert_eq!(c.alerts[0].line, 8);
        match &c.alerts[0].kind {
            RuleKind::Pattern(p) => {
                assert_eq!(p.kind, PatternType::Loss);
                assert_eq!(p.items[1], PatternItem::Any(3));
            }
            k => panic!("{k:?}"),
        }
        match &c.alerts[1].kind {
            RuleKind::Threshold(t) => {
                assert_eq!(t.metric, Metric::Median);
                assert_eq!((t.condition[0].op, t.condition[0].limit), (Op::Gt, 20.0));
                assert_eq!((t.for_rounds, t.clear_rounds), (3, 3));
                assert_eq!(t.clear.as_ref().unwrap()[0].limit, 15.0);
            }
            k => panic!("{k:?}"),
        }
        assert_eq!(c.targets[0].alerts, ["loss-burst"]);
        assert_eq!(c.targets[1].alerts, ["loss-burst", "slow"]);
    }

    #[test]
    fn alert_mistakes_are_reported() {
        let cases: &[(&str, &str, &str)] = &[
            (
                "alerts = [\"loss-burst\"]",
                "alerts = [\"nope\"]",
                "unknown alert \"nope\"",
            ),
            (
                "type    = \"loss\"",
                "type    = \"jitter\"",
                "unknown alert type",
            ),
            (
                "type    = \"loss\"\n",
                "",
                "needs type = \"loss\" or \"rtt\"",
            ),
            (
                "metric    = \"median\"",
                "metric    = \"avg\"",
                "unknown metric \"avg\"",
            ),
            (
                "condition = \"> 20ms\"",
                "condition = \"> 20\"",
                "needs a time unit",
            ),
            (
                "for       = \"3 rounds\"",
                "for       = \"3 minutes\"",
                "number of rounds",
            ),
            (
                "clear     = \"< 15ms\"",
                "clear     = \"< 15%\"",
                "needs a time unit",
            ),
            (
                "pattern = [\">0%\", \"*3*\", \">0%\"]",
                "pattern = [\"*3*\"]",
                "not a wildcard",
            ),
            (
                "pattern = [\">0%\", \"*3*\", \">0%\"]",
                "pattern = [\">0%\"]\nfor = 2",
                "for does not apply to a pattern rule",
            ),
            (
                "name      = \"slow\"",
                "name      = \"loss-burst\"",
                "duplicate alert name",
            ),
        ];
        for (from, to, want) in cases {
            assert!(ALERTS.contains(from), "{from}");
            let src = ALERTS.replacen(from, to, 1);
            let errs = errors(&src);
            assert!(
                errs.iter().any(|e| e.contains(want)),
                "{to:?}: want {want:?} in {errs:?}"
            );
        }
        // A typo in [defaults] is reported even when every target
        // overrides the list.
        let src = ALERTS
            .replacen("alerts = [\"loss-burst\"]", "alerts = [\"los-burst\"]", 1)
            .replace("  name = \"a\"\n", "  name = \"a\"\n  alerts = []\n")
            .replace("alerts = [\"loss-burst\", \"slow\"]", "alerts = []");
        let errs = errors(&src);
        assert!(
            errs.iter()
                .any(|e| e.contains("unknown alert \"los-burst\"")),
            "{errs:?}"
        );
        // A rule no target uses is only a warning.
        let src = ALERTS.replace(", \"slow\"]", "]");
        let p = parse(&src);
        assert!(p.config.is_some());
        assert!(
            p.diagnostics
                .iter()
                .any(|d| d.severity == Severity::Warning
                    && d.message.contains("\"slow\" is not used")),
            "{:?}",
            p.diagnostics
        );
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let p = parse(MINIMAL);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let c = p.config.unwrap();
        assert_eq!(c.server.vantage, "local");
        assert_eq!(c.server.max_pps, 1000);
        let t = &c.targets[0];
        assert_eq!(t.id, "core-fw");
        assert_eq!(t.group, "Core");
        assert_eq!(t.family, Family::V4);
        assert_eq!(t.line, 8);
        assert_eq!(
            t.schedule,
            Schedule {
                step: Duration::from_secs(300),
                pings: 20,
                spread: Duration::from_secs(20),
                timeout: Duration::from_secs(2),
            }
        );
        assert_eq!(t.probe, ProbeConfig::Icmp { payload_size: 56 });
    }

    #[test]
    fn settings_cascade_defaults_group_target() {
        let src = r#"
[server]
data_dir = "/tmp/rl"

[defaults]
step = "60s"
pings = 10
timeout = "1s"

[[group]]
name = "G"
pings = 5

  [[group.target]]
  name = "a"
  host = "example.net"

  [[group.target]]
  name = "b"
  host = "example.org"
  pings = 3
  spread = "6s"
  family = "both"
"#;
        let c = parse(src).config.unwrap();
        assert_eq!(c.targets[0].schedule.step, Duration::from_secs(60));
        assert_eq!(c.targets[0].schedule.pings, 5);
        assert_eq!(c.targets[0].schedule.spread, Duration::from_secs(5));
        assert_eq!(c.targets[1].schedule.pings, 3);
        assert_eq!(c.targets[1].schedule.spread, Duration::from_secs(6));
        assert_eq!(c.targets[1].schedule.timeout, Duration::from_secs(1));
        assert_eq!(c.targets[1].family, Family::Both);
    }

    #[test]
    fn unknown_keys_are_rejected_with_line() {
        let src = "[server]\ndata_dir = \"/x\"\ncolour = \"red\"\n";
        let e = errors(src);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].starts_with("3:1: error:"), "{e:?}");
        assert!(e[0].contains("colour"), "{e:?}");
    }

    #[test]
    fn syntax_errors_have_a_line() {
        let e = errors("[server]\ndata_dir = \n");
        assert_eq!(e.len(), 1);
        assert!(e[0].starts_with("2:"), "{e:?}");
    }

    #[test]
    fn every_invalid_value_is_reported() {
        let src = r#"[server]
data_dir = "/tmp/rl"

[[group]]
name = "G"

  [[group.target]]
  name = "bad name"
  host = "h"
  step = "7s"
  pings = 0
  timeout = "0s"
  size = 4
  family = "v5"
"#;
        let e = errors(src);
        let lines: Vec<&str> = e.iter().map(|s| s.split(':').next().unwrap()).collect();
        assert_eq!(lines, ["8", "10", "11", "12", "13", "14"], "{e:#?}");
    }

    #[test]
    fn duplicate_names_point_at_the_first() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name = "a"
  host = "h"
  [[group.target]]
  name = "a"
  host = "h2"
"#;
        let e = errors(src);
        assert_eq!(e.len(), 1);
        assert!(e[0].starts_with("9:"), "{e:?}");
        assert!(e[0].contains("first defined on line 5"), "{e:?}");
    }

    #[test]
    fn spread_and_timeout_must_fit_in_step() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[defaults]
step = "60s"
[[group]]
name = "G"
  [[group.target]]
  name = "a"
  host = "h"
  pings = 60
"#;
        let e = errors(src);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(
            e[0].contains("ends after the next round starts (step 1m)"),
            "{e:?}"
        );
    }

    #[test]
    fn a_single_ping_only_needs_its_timeout_before_the_next_slot() {
        // Default spread is 1 s, but the only ping goes out at offset 0.
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name = "a"
  host = "h"
  step = "2s"
  pings = 1
  timeout = "1.5s"
"#;
        assert!(errors(src).is_empty(), "{:?}", errors(src));
    }

    #[test]
    fn prefer_v6_accepts_ip_literals() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
family = "prefer-v6"
  [[group.target]]
  name = "a"
  host = "127.0.0.1"
  [[group.target]]
  name = "b"
  host = "::1"
"#;
        assert!(errors(src).is_empty(), "{:?}", errors(src));
    }

    #[test]
    fn nul_in_data_dir_is_rejected() {
        let e = errors("[server]\ndata_dir = \"/tmp/rl\\u0000x\"\n");
        assert!(e.iter().any(|m| m.contains("NUL")), "{e:?}");
    }

    #[test]
    fn unsupported_probe_still_checks_its_settings() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name = "a"
  probe = "http"
  pings = 0
"#;
        let e = errors(src);
        assert_eq!(e.len(), 2, "{e:?}");
    }

    #[test]
    fn rate_budget_is_checked() {
        let mut src = String::from(
            "[server]\ndata_dir = \"/tmp/rl\"\nmax_pps = 1\n[defaults]\nstep = \"10s\"\npings = 5\nspread = \"5s\"\n[[group]]\nname = \"G\"\n",
        );
        for i in 0..3 {
            src.push_str(&format!(
                "[[group.target]]\nname = \"t{i}\"\nhost = \"h\"\n"
            ));
        }
        let e = errors(&src);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].starts_with("1:"), "{e:?}");
        assert!(e[0].contains("1.5 packets/s"), "{e:?}");
    }

    #[test]
    fn literal_family_must_match() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name = "a"
  host = "::1"
  [[group.target]]
  name = "b"
  host = "127.0.0.1"
  family = "v6"
"#;
        let p = parse(src);
        let e: Vec<_> = p.errors().collect();
        assert_eq!(e.len(), 1, "{e:?}");
        assert_eq!(e[0].line, 10);
        assert!(p.config.is_none());
    }

    #[test]
    fn later_probes_get_a_clear_message() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name = "reflector"
  probe = "udp"
  host = "10.0.0.9"
"#;
        let e = errors(src);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("not available yet"), "{e:?}");
    }

    #[test]
    fn tcp_targets_take_a_port_and_mode() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name = "ssh"
  host = "10.0.0.1"
  probe = "tcp"
  port = 22
  mode = "banner"
  [[group.target]]
  name = "web"
  host = "10.0.0.2"
  probe = "tcp"
  port = 443
"#;
        let p = parse(src);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let t = p.config.unwrap().targets;
        assert_eq!(
            t[0].probe,
            ProbeConfig::Tcp {
                port: 22,
                mode: TcpMode::Banner
            }
        );
        assert_eq!(
            t[1].probe,
            ProbeConfig::Tcp {
                port: 443,
                mode: TcpMode::Connect
            }
        );
    }

    #[test]
    fn size_on_a_tcp_target_is_an_error_but_a_shared_size_is_not() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
size = 100
  [[group.target]]
  name = "web"
  host = "h"
  probe = "tcp"
  port = 443
  [[group.target]]
  name = "sized"
  host = "h"
  probe = "tcp"
  port = 443
  size = 64
"#;
        let e = errors(src);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(
            e[0].starts_with("16:") && e[0].contains("size does not apply to tcp targets"),
            "{e:?}"
        );
    }

    #[test]
    fn tcp_settings_are_checked() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name = "noport"
  host = "h"
  probe = "tcp"
  [[group.target]]
  name = "badport"
  host = "h"
  probe = "tcp"
  port = 70000
  mode = "half-open"
  [[group.target]]
  name = "icmp"
  host = "h"
  mode = "banner"
"#;
        let e = errors(src);
        assert_eq!(e.len(), 4, "{e:?}");
        assert!(
            e[0].starts_with("6:") && e[0].contains("needs a port"),
            "{e:?}"
        );
        assert!(
            e[1].starts_with("13:") && e[1].contains("port must"),
            "{e:?}"
        );
        assert!(
            e[2].starts_with("14:") && e[2].contains("mode must"),
            "{e:?}"
        );
        assert!(
            e[3].starts_with("18:") && e[3].contains("does not apply to icmp"),
            "{e:?}"
        );
    }

    #[test]
    fn dns_targets_query_their_server() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name  = "dns-primary"
  probe = "dns"
  server = "10.0.0.53"
  query = "example.com"
  qtype = "A"
  [[group.target]]
  name  = "dns-recursion"
  probe = "dns"
  server = "resolver.example.net"
  query = "{rand}.example.com"
  qtype = "aaaa"
  transport = "tcp"
  port = 5353
  recursion = false
  expect_rcode = "nxdomain"
  expect_answers = ["2001:db8::1"]
"#;
        let p = parse(src);
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let t = p.config.unwrap().targets;
        assert_eq!(t[0].host, "10.0.0.53");
        assert_eq!(
            t[0].probe,
            ProbeConfig::Dns(DnsConfig {
                port: 53,
                query: "example.com".into(),
                qtype: "A".into(),
                transport: DnsTransport::Udp,
                recursion: true,
                expect_rcode: "NOERROR".into(),
                expect_answers: None,
            })
        );
        assert_eq!(t[1].host, "resolver.example.net");
        assert_eq!(
            t[1].probe,
            ProbeConfig::Dns(DnsConfig {
                port: 5353,
                query: "{rand}.example.com".into(),
                qtype: "AAAA".into(),
                transport: DnsTransport::Tcp,
                recursion: false,
                expect_rcode: "NXDOMAIN".into(),
                expect_answers: Some(vec!["2001:db8::1".into()]),
            })
        );
    }

    #[test]
    fn dns_settings_are_checked() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name  = "a"
  probe = "dns"
  host = "10.0.0.53"
  [[group.target]]
  name  = "b"
  probe = "dns"
  server = "10.0.0.53"
  query = "exa mple.com"
  qtype = "BOGUS"
  transport = "quic"
  recursion = "yes"
  expect_answers = []
  mode = "banner"
"#;
        let e = errors(src);
        // a: host instead of server, no server, no query.
        // b: query, qtype, transport, recursion, expect_answers, mode.
        assert_eq!(e.len(), 9, "{e:?}");
        assert!(
            e.iter().any(|m| m.contains("with server, not host")),
            "{e:?}"
        );
        assert!(e.iter().any(|m| m.contains("needs a server")), "{e:?}");
        assert!(e.iter().any(|m| m.contains("needs a query")), "{e:?}");
        assert!(e.iter().any(|m| m.contains("not a domain name")), "{e:?}");
        assert!(e.iter().any(|m| m.contains("qtype \"BOGUS\"")), "{e:?}");
        assert!(
            e.iter().any(|m| m.contains("mode does not apply to dns")),
            "{e:?}"
        );
    }

    #[test]
    fn the_architecture_doc_example_is_valid() {
        // §13.1, with the vantage list trimmed to this machine's.
        let src = r#"[server]
listen_ui     = "0.0.0.0:8080"
listen_agents = "0.0.0.0:4443"
data_dir      = "/var/lib/routelith"

[defaults]
step  = "300s"
pings = 20

[[group]]
name   = "Core"
vantages = ["local", "hasselt", "antwerp"]

  [[group.target]]
  name  = "core-fw"
  host  = "10.0.0.1"
  probe = "icmp"

  [[group.target]]
  name  = "intranet"
  probe = "http"
  url   = "https://intranet.example.local/health"
  expect_status = "200-299"
  metric = "ttfb"

  [[group.target]]
  name   = "dns-primary"
  probe  = "dns"
  server = "10.0.0.53"
  query  = "example.com"
  qtype  = "A"
"#;
        let p = parse(src);
        assert_eq!(p.errors().count(), 0, "{:?}", p.diagnostics);
        let t = p.config.unwrap().targets;
        assert_eq!(t.len(), 3);
        assert_eq!(t[1].host, "intranet.example.local");
        let ProbeConfig::Http(h) = &t[1].probe else {
            panic!("{:?}", t[1].probe)
        };
        assert!(h.tls);
        assert_eq!((h.port, h.path.as_str()), (443, "/health"));
        assert_eq!(h.expect_status, vec![(200, 299)]);
        assert_eq!(h.metric, HttpMetric::Ttfb);
    }

    #[test]
    fn listen_agents_is_an_address_or_off() {
        let at = |v: &str| {
            let p = parse(&format!(
                "[server]\ndata_dir = \"d\"\nlisten_agents = \"{v}\"\n[[group]]\nname = \"g\"\n\
                 [[group.target]]\nname = \"t\"\nhost = \"192.0.2.1\"\n"
            ));
            let errors: Vec<String> = p.errors().map(|d| d.message.clone()).collect();
            (p.config.map(|c| c.server.listen_agents), errors)
        };
        let (a, e) = at("0.0.0.0:4443");
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(a, Some(Some("0.0.0.0:4443".parse().unwrap())));
        assert_eq!(at("off").0, Some(None));
        let (a, e) = at("4443");
        assert!(a.is_none());
        assert!(
            e.iter().any(|m| m.contains("listen_agents must be")),
            "{e:?}"
        );
    }

    #[test]
    fn http_settings_are_checked() {
        let src = r#"[server]
data_dir = "/tmp/rl"
[[group]]
name = "G"
  [[group.target]]
  name  = "nourl"
  probe = "http"
  [[group.target]]
  name  = "badurl"
  probe = "http"
  url   = "ftp://x/"
  [[group.target]]
  name  = "bad"
  probe = "http"
  url   = "http://[2001:db8::1]:8080/x"
  host  = "h"
  expect_status = "299-200"
  metric = "tls"
  method = "POST"
  tls_verify = "no"
  [[group.target]]
  name  = "insecure"
  probe = "https"
  url   = "https://h.example/"
  tls_verify = false
"#;
        let p = parse(src);
        let e: Vec<String> = p.errors().map(ToString::to_string).collect();
        assert_eq!(e.len(), 7, "{e:?}");
        assert!(e.iter().any(|m| m.contains("needs a url")), "{e:?}");
        assert!(
            e.iter().any(|m| m.contains("url must start with http")),
            "{e:?}"
        );
        assert!(
            e.iter().any(|m| m.contains("take their host from url")),
            "{e:?}"
        );
        assert!(e.iter().any(|m| m.contains("runs backwards")), "{e:?}");
        assert!(e.iter().any(|m| m.contains("needs an https url")), "{e:?}");
        assert!(e.iter().any(|m| m.contains("method must")), "{e:?}");
        assert!(e.iter().any(|m| m.contains("tls_verify must")), "{e:?}");
        let w: Vec<_> = p
            .diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .collect();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].message.contains("accepts any certificate"));
    }

    #[test]
    fn urls() {
        let u = parse_http_url("https://Example.org").unwrap();
        assert_eq!(
            (u.tls, u.host.as_str(), u.port, u.path.as_str()),
            (true, "Example.org", 443, "/")
        );
        let u = parse_http_url("http://[::1]:8080?q=1").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.path.as_str()),
            ("::1", 8080, "/?q=1")
        );
        for bad in [
            "example.org",
            "http://",
            "http://user:pw@h/",
            "http://h:0/",
            "http://h:99999/",
            "http://[zz]/",
            "http://h/#x",
            "http://h /",
        ] {
            assert!(parse_http_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn status_ranges() {
        assert_eq!(parse_status_ranges("200-299"), Ok(vec![(200, 299)]));
        assert_eq!(
            parse_status_ranges("200, 301-302"),
            Ok(vec![(200, 200), (301, 302)])
        );
        assert!(parse_status_ranges("99").is_err());
        assert!(parse_status_ranges("200-").is_err());
    }

    #[test]
    fn dns_query_names_are_checked_as_sent() {
        let target = |query: &str, extra: &str| {
            format!(
                "[server]\ndata_dir = \"/x\"\n[[group]]\nname = \"G\"\n[[group.target]]\n\
                 name = \"a\"\nprobe = \"dns\"\nserver = \"10.0.0.53\"\nquery = \"{query}\"\n{extra}"
            )
        };
        // The root, for example for NS.
        assert!(errors(&target(".", "qtype = \"NS\"\n")).is_empty());
        // {rand} becomes 12 characters: 51 + 12 = 63 fits a label, 52 + 12 does not.
        let fits = format!("{}{{rand}}.example.com", "a".repeat(51));
        assert!(errors(&target(&fits, "")).is_empty());
        let too_long = format!("{}{{rand}}.example.com", "a".repeat(52));
        assert_eq!(errors(&target(&too_long, "")).len(), 1);
        // DS and DNSKEY answers are not decoded, so they cannot be expected.
        let e = errors(&target(
            "example.com",
            "qtype = \"DS\"\nexpect_answers = [\"1 2 3 ab\"]\n",
        ));
        assert!(
            e.len() == 1 && e[0].contains("not supported for DS"),
            "{e:?}"
        );
    }

    #[test]
    fn keys_of_other_probes_are_rejected_on_icmp() {
        let src = "[server]\ndata_dir = \"/x\"\n[[group]]\nname = \"G\"\n[[group.target]]\nname = \"a\"\nhost = \"h\"\nport = 443\n";
        let e = errors(src);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].starts_with("8:8:"), "{e:?}");
    }

    #[test]
    fn other_vantages_are_skipped_with_a_warning() {
        let src = r#"[server]
data_dir = "/tmp/rl"
listen_ui = "0.0.0.0:8080"
[[group]]
name = "Remote"
vantages = ["hasselt"]
  [[group.target]]
  name = "a"
  host = "h"
"#;
        let p = parse(src);
        assert_eq!(p.errors().count(), 0);
        assert_eq!(p.diagnostics.len(), 2, "{:?}", p.diagnostics);
        assert!(p.config.unwrap().targets.is_empty());
    }

    #[test]
    fn ui_login_and_tls_settings() {
        let base = "[server]\ndata_dir = \"/var/lib/rl\"\n";
        let c = parse(base).config.unwrap().server;
        assert_eq!(c.users_file, PathBuf::from("/var/lib/rl/users.toml"));
        assert!(!c.anonymous);
        assert_eq!(c.tls, None);

        let src = format!(
            "{base}listen_ui = \"0.0.0.0:8443\"\nusers_file = \"/etc/rl/users.toml\"\n\
             anonymous = true\ntls_cert = \"/etc/rl/ui.pem\"\ntls_key = \"/etc/rl/ui.key\"\n"
        );
        let p = parse(&src);
        // TLS is set, so a public address draws no warning.
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        let c = p.config.unwrap().server;
        assert_eq!(c.users_file, PathBuf::from("/etc/rl/users.toml"));
        assert!(c.anonymous);
        assert_eq!(
            c.tls,
            Some(UiTls {
                cert: "/etc/rl/ui.pem".into(),
                key: "/etc/rl/ui.key".into()
            })
        );

        let p = parse(&format!("{base}listen_ui = \"0.0.0.0:8080\"\n"));
        let w: Vec<_> = p.diagnostics.iter().map(ToString::to_string).collect();
        assert!(w.len() == 1 && w[0].contains("without TLS"), "{w:?}");

        let e = errors(&format!("{base}tls_cert = \"/a.pem\"\n"));
        assert!(
            e.len() == 1 && e[0].contains("tls_cert and tls_key go together"),
            "{e:?}"
        );
        let e = errors(&format!("{base}users_file = \" \"\n"));
        assert!(
            e.len() == 1 && e[0].contains("users_file must be a file path"),
            "{e:?}"
        );
    }

    #[test]
    fn shipped_example_is_valid() {
        let p = parse(include_str!("../../../examples/routelith.toml"));
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        assert_eq!(p.config.unwrap().targets.len(), 6);
    }

    #[test]
    fn bad_inherited_values_are_reported_once_where_declared() {
        let src = r#"
[server]
data_dir = "/tmp/rl"

[defaults]
step = "7s"

[[group]]
name = "G"
pings = 0

  [[group.target]]
  name = "a"
  host = "10.0.0.1"
  step = "60s"
  pings = 5

  [[group.target]]
  name = "b"
  host = "10.0.0.2"
"#;
        let e = errors(src);
        assert_eq!(e.len(), 2, "{e:?}");
        assert!(
            e[0].starts_with("6:8: error: step must be whole seconds"),
            "{e:?}"
        );
        assert!(e[1].starts_with("10:9: error: pings must be"), "{e:?}");
    }

    #[test]
    fn host_problems_do_not_hide_setting_errors() {
        let src = r#"
[server]
data_dir = "/tmp/rl"

[[group]]
name = "G"

  [[group.target]]
  name = "a"
  pings = 0

  [[group.target]]
  name = "b"
  host = "https://example.org/health"
"#;
        let e = errors(src);
        assert_eq!(e.len(), 3, "{e:?}");
        assert!(e[0].contains("needs a host"), "{e:?}");
        assert!(e[1].contains("pings must be"), "{e:?}");
        assert!(e[2].contains("not a URL"), "{e:?}");
    }

    #[test]
    fn host_names() {
        for ok in [
            "example.org",
            "example.org.",
            "a_b.example",
            "localhost",
            "xn--bcher-kva.ch",
        ] {
            assert!(valid_hostname(ok), "{ok}");
        }
        for bad in [
            "",
            ".",
            "a..b",
            "-a.org",
            "a-.org",
            "http://a.org",
            "a.org/x",
            "a b",
        ] {
            assert!(!valid_hostname(bad), "{bad}");
        }
    }

    #[test]
    fn an_exactly_full_packet_budget_is_accepted() {
        let mut src = String::from(
            "[server]\ndata_dir = \"/tmp/rl\"\nmax_pps = 1\n[defaults]\nstep = \"20s\"\npings = 1\n\
             [[group]]\nname = \"G\"\n",
        );
        for i in 0..20 {
            src += &format!(
                "[[group.target]]\nname = \"t{i}\"\nhost = \"10.0.0.{}\"\n",
                i + 1
            );
        }
        assert!(errors(&src).is_empty(), "{:?}", errors(&src));
        src += "[[group.target]]\nname = \"t20\"\nhost = \"10.0.1.1\"\n";
        assert!(errors(&src)[0].contains("above max_pps = 1"));
    }

    #[test]
    fn positions_count_characters() {
        let position = |src: &str, offset| {
            Validator {
                src,
                line_starts: line_starts(src),
                diagnostics: Vec::new(),
                errors: 0,
                alert_names: HashMap::new(),
            }
            .position(offset)
        };
        assert_eq!(position("ab\ncµd", 6), (2, 3));
        assert_eq!(position("ab\n", 3), (2, 1));
        assert_eq!(position("", 0), (1, 1));
    }

    #[test]
    fn data_dir_keeps_its_spaces() {
        let src = MINIMAL.replace("data_dir = \"/tmp/rl\"", "data_dir = \"/tmp/rl \"");
        let cfg = parse(&src).config.unwrap();
        assert_eq!(cfg.server.data_dir, PathBuf::from("/tmp/rl "));
    }

    #[test]
    fn control_characters_are_escaped() {
        assert_eq!(escape_controls("a\u{1b}[2Jb\tc"), "a\\u{1b}[2Jb\\tc");
        assert_eq!(escape_controls("a\nb\rc"), "a\\nb\\rc");
    }

    #[test]
    fn a_quoted_key_cannot_forge_a_diagnostic_line() {
        let src = format!("{MINIMAL}\"x\\nconfig.toml:1:1: error: forged\" = 1\n");
        let parsed = parse(&src);
        assert!(parsed.config.is_none());
        let d = parsed
            .diagnostics
            .iter()
            .find(|d| d.message.contains("forged"))
            .unwrap();
        assert!(!d.message.contains('\n'), "{:?}", d.message);
        assert!(d.message.contains("x\\nconfig.toml"), "{:?}", d.message);
        assert_eq!(d.line, src.lines().count());
        assert!(!d.to_string().contains('\n'));
    }
}
