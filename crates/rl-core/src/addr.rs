//! Address classes for trace hops (architecture doc §21.9 P9): ranges that
//! are never routed on the internet get a built-in label, so a hop such as
//! 10.0.0.1 or 100.64.0.1 reads as "private" or "CGNAT" without an ASN
//! database.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What kind of address a hop has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddrClass {
    /// Globally routed (as far as these built-in ranges know).
    Public,
    /// RFC 1918 (10/8, 172.16/12, 192.168/16) and IPv6 unique local (fc00::/7).
    Private,
    /// Carrier-grade NAT shared space, 100.64.0.0/10 (RFC 6598).
    Cgnat,
    Loopback,
    /// 169.254/16 and fe80::/10.
    LinkLocal,
    /// 192.0.2/24, 198.51.100/24, 203.0.113/24 and 2001:db8::/32.
    Documentation,
    Multicast,
    /// Other ranges that are never routed: 0/8, 192.0.0/24, 198.18/15
    /// (benchmarking), 240/4, broadcast, ::, IPv4-mapped and the like.
    Bogon,
}

impl AddrClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Cgnat => "cgnat",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link_local",
            Self::Documentation => "documentation",
            Self::Multicast => "multicast",
            Self::Bogon => "bogon",
        }
    }

    /// Whether an ASN lookup can mean anything for this class.
    pub fn is_public(self) -> bool {
        self == Self::Public
    }
}

/// The class of an address.
pub fn classify(addr: IpAddr) -> AddrClass {
    match addr {
        IpAddr::V4(a) => classify_v4(a),
        IpAddr::V6(a) => classify_v6(a),
    }
}

fn in_v4(a: Ipv4Addr, net: [u8; 4], len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    u32::from(a) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn classify_v4(a: Ipv4Addr) -> AddrClass {
    use AddrClass::*;
    let table: &[([u8; 4], u32, AddrClass)] = &[
        ([10, 0, 0, 0], 8, Private),
        ([172, 16, 0, 0], 12, Private),
        ([192, 168, 0, 0], 16, Private),
        ([100, 64, 0, 0], 10, Cgnat),
        ([127, 0, 0, 0], 8, Loopback),
        ([169, 254, 0, 0], 16, LinkLocal),
        ([192, 0, 2, 0], 24, Documentation),
        ([198, 51, 100, 0], 24, Documentation),
        ([203, 0, 113, 0], 24, Documentation),
        ([224, 0, 0, 0], 4, Multicast),
        ([0, 0, 0, 0], 8, Bogon),
        ([192, 0, 0, 0], 24, Bogon),
        ([198, 18, 0, 0], 15, Bogon),
        ([240, 0, 0, 0], 4, Bogon),
    ];
    table
        .iter()
        .find(|(net, len, _)| in_v4(a, *net, *len))
        .map_or(Public, |&(_, _, c)| c)
}

fn classify_v6(a: Ipv6Addr) -> AddrClass {
    use AddrClass::*;
    let s = a.segments();
    if a.is_loopback() {
        return Loopback;
    }
    if a.is_unspecified() {
        return Bogon;
    }
    // IPv4-mapped (::ffff:0:0/96): the IPv4 address's class.
    if let Some(v4) = a.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    match s[0] {
        0xfc00..=0xfdff => Private,
        0xfe80..=0xfebf => LinkLocal,
        0xff00..=0xffff => Multicast,
        0x2001 if s[1] == 0x0db8 => Documentation,
        // 3fff::/20 (RFC 9637) is documentation too.
        0x3fff if s[1] < 0x1000 => Documentation,
        // Only 2000::/3 is global unicast today.
        0x2000..=0x3fff => Public,
        _ => Bogon,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> AddrClass {
        classify(s.parse().unwrap())
    }

    #[test]
    fn built_in_ranges() {
        assert_eq!(c("10.1.2.3"), AddrClass::Private);
        assert_eq!(c("172.31.255.1"), AddrClass::Private);
        assert_eq!(c("172.32.0.1"), AddrClass::Public);
        assert_eq!(c("192.168.1.1"), AddrClass::Private);
        assert_eq!(c("100.64.0.1"), AddrClass::Cgnat);
        assert_eq!(c("100.127.255.254"), AddrClass::Cgnat);
        assert_eq!(c("100.128.0.1"), AddrClass::Public);
        assert_eq!(c("169.254.1.1"), AddrClass::LinkLocal);
        assert_eq!(c("192.0.2.1"), AddrClass::Documentation);
        assert_eq!(c("198.18.0.1"), AddrClass::Bogon);
        assert_eq!(c("255.255.255.255"), AddrClass::Bogon);
        assert_eq!(c("1.1.1.1"), AddrClass::Public);
        assert_eq!(c("fd00::1"), AddrClass::Private);
        assert_eq!(c("fe80::1"), AddrClass::LinkLocal);
        assert_eq!(c("2001:db8::1"), AddrClass::Documentation);
        assert_eq!(c("2606:4700::1111"), AddrClass::Public);
        assert_eq!(c("::ffff:10.0.0.1"), AddrClass::Private);
        assert_eq!(c("::1"), AddrClass::Loopback);
        assert_eq!(c("::"), AddrClass::Bogon);
        assert_eq!(c("ff02::1"), AddrClass::Multicast);
    }
}
