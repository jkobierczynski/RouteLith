//! The agent's local allow-list (§21.7 G6, §14): what this agent agrees to
//! measure, whatever the server asks, so a rogue or broken server cannot
//! turn it into a scanner.
//!
//! `allow = [...]` in agent.toml holds two kinds of entries:
//!
//! - where: an address or network (`192.0.2.1`, `10.0.0.0/8`,
//!   `2001:db8::/32`), a host name (`erp.example.be`) or every name under
//!   a domain (`*.example.be`);
//! - how: a probe type, optionally with a port (`icmp`, `tcp`, `tcp:443`,
//!   `dns`, `dns:53`, `http`, `http:8080`).
//!
//! A target must match a "where" entry when there are any, and a "how"
//! entry when there are any; an empty list allows everything. A target
//! named by host name passes a network entry only for the address each
//! round resolves to, so a name that later points elsewhere is still
//! held to the list.

use std::net::IpAddr;

use rl_core::config::ProbeConfig;

use crate::FedError;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Where {
    Net(IpAddr, u8),
    Name(String),
    /// `*.example.be`: names under `example.be`, stored with the dot.
    Under(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct How {
    kind: &'static str,
    port: Option<u16>,
}

const KINDS: [&str; 4] = ["icmp", "tcp", "dns", "http"];

/// The parsed allow-list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowList {
    wheres: Vec<Where>,
    hows: Vec<How>,
}

/// What [`AllowList::check`] decided for a series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    /// Allowed for the addresses the list covers: check each round's.
    EachRound,
    Refused(String),
}

impl AllowList {
    pub fn parse(entries: &[String]) -> Result<AllowList, FedError> {
        let mut list = AllowList::default();
        for e in entries {
            let bad = |why: &str| FedError::Invalid(format!("allow: {e:?}: {why}"));
            let s = e.trim().to_ascii_lowercase();
            if s.is_empty() {
                return Err(bad("empty entry"));
            }
            let (head, port) = match s.split_once(':') {
                Some((h, p)) if KINDS.contains(&h) => (h, Some(p)),
                _ => (s.as_str(), None),
            };
            if let Some(&kind) = KINDS.iter().find(|k| **k == head) {
                let port = match port {
                    None => None,
                    Some(_) if kind == "icmp" => return Err(bad("icmp has no port")),
                    Some(p) => Some(
                        p.parse::<u16>()
                            .ok()
                            .filter(|p| *p > 0)
                            .ok_or_else(|| bad("the port must be 1 to 65535"))?,
                    ),
                };
                list.hows.push(How { kind, port });
                continue;
            }
            list.wheres.push(parse_where(&s).ok_or_else(|| {
                bad(
                    "give an address, a network (10.0.0.0/8), a host name, *.domain, \
                     or a probe type (icmp, tcp, tcp:443, dns, http)",
                )
            })?);
        }
        Ok(list)
    }

    pub fn is_empty(&self) -> bool {
        self.wheres.is_empty() && self.hows.is_empty()
    }

    /// Whether the agent takes a series of `host` measured with `probe`.
    pub fn check(&self, host: &str, probe: &ProbeConfig) -> Verdict {
        let (kind, port) = match probe {
            ProbeConfig::Icmp { .. } => ("icmp", None),
            ProbeConfig::Tcp { port, .. } => ("tcp", Some(*port)),
            ProbeConfig::Dns(d) => ("dns", Some(d.port)),
            ProbeConfig::Http(h) => ("http", Some(h.port)),
        };
        if !self.hows.is_empty()
            && !self
                .hows
                .iter()
                .any(|h| h.kind == kind && (h.port.is_none() || h.port == port))
        {
            let what = match port {
                Some(p) => format!("{kind} port {p}"),
                None => kind.to_string(),
            };
            return Verdict::Refused(format!("{what} is not in this agent's allow list"));
        }
        if self.wheres.is_empty() {
            return Verdict::Allowed;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let literal = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .ok();
        if let Some(addr) = literal {
            return if self.allows_addr(addr) {
                Verdict::Allowed
            } else {
                Verdict::Refused(format!("{addr} is not in this agent's allow list"))
            };
        }
        let named = self.wheres.iter().any(|w| match w {
            Where::Name(n) => *n == host,
            Where::Under(d) => host.ends_with(d.as_str()),
            Where::Net(..) => false,
        });
        if named {
            Verdict::Allowed
        } else if self.wheres.iter().any(|w| matches!(w, Where::Net(..))) {
            Verdict::EachRound
        } else {
            Verdict::Refused(format!("{host} is not in this agent's allow list"))
        }
    }

    /// Whether an address is in one of the networks.
    pub fn allows_addr(&self, addr: IpAddr) -> bool {
        let addr = canonical(addr);
        self.wheres.iter().any(|w| match w {
            Where::Net(net, len) => contains(*net, *len, addr),
            _ => false,
        })
    }
}

fn parse_where(s: &str) -> Option<Where> {
    if let Some((a, len)) = s.split_once('/') {
        let addr: IpAddr = a.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len: u8 = len.parse().ok().filter(|l| *l <= max)?;
        return Some(Where::Net(canonical(addr), len));
    }
    if let Ok(addr) = s
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        let len = if addr.is_ipv4() { 32 } else { 128 };
        return Some(Where::Net(canonical(addr), len));
    }
    let (under, name) = match s.strip_prefix("*.") {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let name = name.trim_end_matches('.');
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if name.is_empty() || name.len() > 253 || !name.split('.').all(label_ok) {
        return None;
    }
    Some(if under {
        Where::Under(format!(".{name}"))
    } else {
        Where::Name(name.to_string())
    })
}

/// IPv4-mapped IPv6 addresses count as IPv4.
fn canonical(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

fn contains(net: IpAddr, len: u8, addr: IpAddr) -> bool {
    match (net, addr) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(n) & mask == u32::from(a) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(n) & mask == u128::from(a) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_core::config::TcpMode;

    fn list(e: &[&str]) -> AllowList {
        AllowList::parse(&e.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn tcp(port: u16) -> ProbeConfig {
        ProbeConfig::Tcp {
            port,
            mode: TcpMode::Connect,
        }
    }

    const ICMP: ProbeConfig = ProbeConfig::Icmp { payload_size: 56 };

    #[test]
    fn an_empty_list_allows_everything() {
        let l = list(&[]);
        assert!(l.is_empty());
        assert_eq!(l.check("203.0.113.9", &ICMP), Verdict::Allowed);
    }

    #[test]
    fn networks_and_names() {
        let l = list(&[
            "10.0.0.0/8",
            "2001:DB8::/32",
            "erp.example.be",
            "*.plant.example",
        ]);
        assert_eq!(l.check("10.1.2.3", &ICMP), Verdict::Allowed);
        assert_eq!(l.check("[2001:db8::1]", &ICMP), Verdict::Allowed);
        assert!(matches!(l.check("192.0.2.1", &ICMP), Verdict::Refused(_)));
        assert_eq!(l.check("ERP.example.be.", &ICMP), Verdict::Allowed);
        assert_eq!(l.check("plc.plant.example", &ICMP), Verdict::Allowed);
        // Not the domain itself, nor a name that only ends the same way.
        assert_eq!(l.check("plant.example", &ICMP), Verdict::EachRound);
        assert_eq!(l.check("xplant.example", &ICMP), Verdict::EachRound);
        assert!(l.allows_addr("10.255.0.1".parse().unwrap()));
        assert!(l.allows_addr("::ffff:10.0.0.1".parse().unwrap()));
        assert!(!l.allows_addr("11.0.0.1".parse().unwrap()));
        // Names only: an unlisted name is refused outright.
        let l = list(&["erp.example.be"]);
        assert!(matches!(
            l.check("other.example.be", &ICMP),
            Verdict::Refused(_)
        ));
        assert!(matches!(l.check("10.0.0.1", &ICMP), Verdict::Refused(_)));
        let l = list(&["0.0.0.0/0"]);
        assert_eq!(l.check("198.51.100.1", &ICMP), Verdict::Allowed);
    }

    #[test]
    fn probe_types_and_ports() {
        let l = list(&["icmp", "tcp:443"]);
        assert_eq!(l.check("192.0.2.1", &ICMP), Verdict::Allowed);
        assert_eq!(l.check("192.0.2.1", &tcp(443)), Verdict::Allowed);
        let Verdict::Refused(why) = l.check("192.0.2.1", &tcp(22)) else {
            panic!("tcp 22 allowed")
        };
        assert!(why.contains("tcp port 22"), "{why}");
        // Both kinds: a target must pass each.
        let l = list(&["tcp", "192.0.2.0/24"]);
        assert_eq!(l.check("192.0.2.1", &tcp(22)), Verdict::Allowed);
        assert!(matches!(l.check("192.0.2.1", &ICMP), Verdict::Refused(_)));
        assert!(matches!(
            l.check("198.51.100.1", &tcp(22)),
            Verdict::Refused(_)
        ));
    }

    #[test]
    fn mistakes_are_reported() {
        for bad in [
            "",
            "10.0.0.0/33",
            "::/129",
            "icmp:1",
            "tcp:0",
            "tcp:x",
            "a b",
            "-x.be",
            "*.",
            "x/8",
        ] {
            assert!(AllowList::parse(&[bad.to_string()]).is_err(), "{bad:?}");
        }
    }
}
