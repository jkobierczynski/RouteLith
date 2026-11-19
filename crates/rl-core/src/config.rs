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

use crate::duration;

/// Seconds in a day; steps must divide it so rounds stay aligned to UTC days.
const DAY_SECS: u64 = 86_400;
const DEFAULT_STEP: Duration = Duration::from_secs(300);
const DEFAULT_PINGS: u16 = 20;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_SIZE: u16 = 56;
const DEFAULT_MAX_PPS: u32 = 1_000;
const DEFAULT_VANTAGE: &str = "local";
const MAX_PINGS: i64 = 1_000;
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// Largest ICMP payload that fits one IPv4 datagram.
const MAX_SIZE: i64 = 65_507;
/// Smallest payload: it carries the 8-byte nonce.
const MIN_SIZE: i64 = 8;
const MAX_NAME_LEN: usize = 64;

/// A validated configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub server: ServerConfig,
    /// Targets measured from this vantage, in file order.
    pub targets: Vec<TargetConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub data_dir: PathBuf,
    /// Name of this vantage point; `local` unless set.
    pub vantage: String,
    /// Packets-per-second ceiling for the whole agent (§5.2).
    pub max_pps: u32,
}

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
    /// 1-based line of the target's table, for messages.
    pub line: usize,
}

/// The probe of a target and its settings (architecture doc §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeConfig {
    /// ICMP echo with this many payload bytes.
    Icmp { payload_size: u16 },
    /// TCP connect time to `port` (§4.3).
    Tcp { port: u16, mode: TcpMode },
}

impl ProbeConfig {
    /// The `probe` value that selects this probe.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Icmp { .. } => "icmp",
            Self::Tcp { .. } => "tcp",
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
                }
            }
        }
    };
}

settings_struct!(RawDefaults {});

settings_struct!(RawGroup {
    name: Spanned<String>,
    vantages: Option<Spanned<Vec<String>>>,
    #[serde(default, rename = "target")]
    targets: Vec<Spanned<RawTarget>>,
});

settings_struct!(RawTarget {
    name: Spanned<String>,
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
});

// ---- validation -----------------------------------------------------------

struct Validator<'a> {
    src: &'a str,
    /// Byte offset of each line's start.
    line_starts: Vec<usize>,
    diagnostics: Vec<Diagnostic>,
    errors: usize,
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
        self.check_layer(&defaults);

        let mut targets = Vec::new();
        let mut group_names: HashMap<String, Range<usize>> = HashMap::new();
        let mut target_names: HashMap<String, usize> = HashMap::new();
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
                let t = self.target(&target, &gname, &settings, span);
                if let (Some(t), true) = (t, measured_here) {
                    targets.push(t);
                }
            }
        }

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
        Some(Config { server, targets })
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
        for (key, value) in [
            ("listen_ui", &raw.listen_ui),
            ("listen_agents", &raw.listen_agents),
        ] {
            if let Some(v) = value {
                self.warning(
                    &v.span(),
                    format!("{key} is ignored until M1 (no web UI or agents yet)"),
                );
            }
        }
        ok.then(|| ServerConfig {
            data_dir: PathBuf::from(data_dir),
            vantage,
            max_pps,
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
            Some((probe, p)) => {
                let msg = if ["udp", "dns", "http", "https"].contains(&p) {
                    format!(
                        "probe {p:?} is not available yet; this version measures \"icmp\" and \"tcp\""
                    )
                } else {
                    format!("unknown probe {p:?}; this version measures \"icmp\" and \"tcp\"")
                };
                self.error(&probe.span(), msg);
                // Still check the target's own schedule values.
                self.check_layer(s);
                return None;
            }
        };
        for (key, value, applies) in [
            ("url", &raw.url, false),
            ("expect_status", &raw.expect_status, false),
            ("metric", &raw.metric, false),
            ("server", &raw.server, false),
            ("query", &raw.query, false),
            ("qtype", &raw.qtype, false),
            ("port", &raw.port, kind == "tcp"),
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
        let tcp = if kind == "tcp" { self.tcp(raw) } else { None };
        // A host problem is recorded, but the settings are still checked.
        let host = match &raw.host {
            Some(h) if !h.get_ref().trim().is_empty() => Some(h),
            Some(h) => {
                self.error(&h.span(), "host must not be empty");
                None
            }
            None => {
                self.error(&raw.name.span(), format!("target {name:?} needs a host"));
                None
            }
        };
        let literal: Option<IpAddr> = host.and_then(|h| h.get_ref().trim().parse().ok());
        if let (Some(h), None) = (host, literal) {
            if !valid_hostname(h.get_ref().trim()) {
                self.error(
                    &h.span(),
                    format!(
                        "host {:?} is neither an IP address nor a host name \
                         ({kind} targets take a bare name such as \"example.org\", not a URL)",
                        h.get_ref()
                    ),
                );
            }
        }

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
                "tcp" => tcp?,
                _ => ProbeConfig::Icmp {
                    payload_size: size?,
                },
            },
            line: self.position(span.start).0,
        })
    }

    /// The TCP settings of a target: `port` (required) and `mode`.
    fn tcp(&mut self, raw: &RawTarget) -> Option<ProbeConfig> {
        let port = match &raw.port {
            None => {
                self.error(
                    &raw.name.span(),
                    format!("tcp target {:?} needs a port", raw.name.get_ref()),
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
        };
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
  name = "intranet"
  probe = "http"
  url = "https://intranet.example.local/health"
  expect_status = "200-299"
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
    fn shipped_example_is_valid() {
        let p = parse(include_str!("../../../examples/routelith.toml"));
        assert!(p.diagnostics.is_empty(), "{:?}", p.diagnostics);
        assert_eq!(p.config.unwrap().targets.len(), 4);
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
