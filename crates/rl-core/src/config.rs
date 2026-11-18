//! TOML configuration (architecture doc §13.1), M0 subset.
//!
//! Settings cascade `[defaults]` → `[[group]]` → `[[group.target]]`. Every
//! problem is reported with its line and column, and all of them are
//! reported at once rather than stopping at the first.
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
    /// ICMP payload bytes.
    pub payload_size: u16,
    /// 1-based line of the target's table, for messages.
    pub line: usize,
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
        let data_dir = raw.data_dir.get_ref().trim();
        if data_dir.is_empty() {
            self.error(&raw.data_dir.span(), "data_dir must not be empty");
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
        if let Some(probe) = raw.probe.as_ref().filter(|p| p.get_ref() != "icmp") {
            let p = probe.get_ref();
            let msg = if ["tcp", "udp", "dns", "http", "https"].contains(&p.as_str()) {
                format!("probe {p:?} is not available until M1; M0 measures \"icmp\" only")
            } else {
                format!("unknown probe {p:?}; M0 measures \"icmp\" only")
            };
            self.error(&probe.span(), msg);
            return None;
        }
        for (key, value) in [
            ("url", &raw.url),
            ("expect_status", &raw.expect_status),
            ("metric", &raw.metric),
            ("server", &raw.server),
            ("query", &raw.query),
            ("qtype", &raw.qtype),
            ("port", &raw.port),
        ] {
            if let Some(v) = value {
                self.error(&v.span(), format!("{key} does not apply to icmp targets"));
            }
        }
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
                         (icmp targets take a bare name such as \"example.org\", not a URL)",
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

        let overrun = match (step, spread, timeout) {
            (Some(step), Some(spread), Some(timeout)) if spread + timeout > step => {
                Some((step, spread, timeout))
            }
            _ => None,
        };
        if let Some((step, spread, timeout)) = overrun {
            let at = s.spread.as_ref().map_or(raw.name.span(), Spanned::span);
            self.error(
                &at,
                format!(
                    "target {name:?}: spread ({}) plus timeout ({}) exceeds step ({}), so every \
                     round would overrun; set a shorter spread or a longer step",
                    duration::format(spread),
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
            payload_size: size?,
            line: self.position(span.start).0,
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
            (Some(lf), Some(host)) if family != lf => {
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

/// Control characters (from quoted keys or values) escaped, so a message
/// cannot rewrite the terminal it is printed on. Line breaks stay.
fn escape_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() && c != '\n' {
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
        assert_eq!(t.payload_size, 56);
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
        assert!(e[0].contains("exceeds step (1m)"), "{e:?}");
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
        assert!(e[0].contains("not available until M1"), "{e:?}");
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
        assert_eq!(p.config.unwrap().targets.len(), 3);
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
    fn control_characters_are_escaped() {
        assert_eq!(escape_controls("a\u{1b}[2Jb\tc"), "a\\u{1b}[2Jb\\tc");
    }
}
