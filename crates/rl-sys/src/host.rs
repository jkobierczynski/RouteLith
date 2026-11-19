//! Readings of this machine's own health for the local health snapshot
//! (architecture doc §19, §21.3): CPU time, NIC error and drop counters,
//! default gateways and DNS servers.
//!
//! [`read`] returns cumulative counters; the caller turns two readings into
//! a snapshot. On Linux everything comes from `/proc` and `resolv.conf`; on
//! Windows from `GetSystemTimes` and the IP Helper API. Anything that cannot
//! be read is left empty rather than failing the whole reading. Other
//! systems (macOS, best effort) return an empty reading.

use std::net::IpAddr;
#[cfg(any(target_os = "linux", test))]
use std::net::{Ipv4Addr, Ipv6Addr};

/// CPU time since boot, in any unit, summed over all CPUs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    /// Time spent not idle (I/O wait counts as idle).
    pub busy: u64,
    pub total: u64,
}

/// Error and drop counters of one network interface since it came up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NicCounters {
    pub name: String,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_drops: u64,
    pub tx_drops: u64,
}

/// One reading of the host.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostReading {
    pub cpu: Option<CpuTimes>,
    /// One-minute load average (Linux only).
    pub load1: Option<f64>,
    /// Interfaces other than loopback, sorted by name.
    pub nics: Vec<NicCounters>,
    /// Next hops of the default routes, IPv4 first, without duplicates.
    pub gateways: Vec<IpAddr>,
    /// Configured DNS servers in resolver order, without duplicates.
    pub dns_servers: Vec<IpAddr>,
}

/// Read the host now. Cheap enough to call once a minute; blocking.
pub fn read() -> HostReading {
    #[cfg(target_os = "linux")]
    let mut r = read_linux();
    #[cfg(windows)]
    let mut r = crate::windows::read_host();
    #[cfg(not(any(target_os = "linux", windows)))]
    let mut r = HostReading::default();
    r.nics.sort_by(|a, b| a.name.cmp(&b.name));
    dedup(&mut r.gateways);
    dedup(&mut r.dns_servers);
    r
}

/// Drop repeated addresses, keeping the first of each.
fn dedup(v: &mut Vec<IpAddr>) {
    let mut seen = Vec::with_capacity(v.len());
    v.retain(|a| {
        if seen.contains(a) {
            false
        } else {
            seen.push(*a);
            true
        }
    });
}

#[cfg(target_os = "linux")]
fn read_linux() -> HostReading {
    let file = |p: &str| std::fs::read_to_string(p).ok();
    let mut gateways = file("/proc/net/route")
        .map(|s| parse_route(&s))
        .unwrap_or_default();
    gateways.extend(
        file("/proc/net/ipv6_route")
            .map(|s| parse_ipv6_route(&s))
            .unwrap_or_default(),
    );
    let mut dns_servers = file("/etc/resolv.conf")
        .map(|s| parse_resolv_conf(&s))
        .unwrap_or_default();
    // A local stub resolver (systemd-resolved's 127.0.0.53) hides the
    // servers actually used; resolved lists them in its own file.
    if !dns_servers.is_empty() && dns_servers.iter().all(IpAddr::is_loopback) {
        if let Some(upstream) = file("/run/systemd/resolve/resolv.conf")
            .map(|s| parse_resolv_conf(&s))
            .filter(|v| !v.is_empty())
        {
            dns_servers = upstream;
        }
    }
    HostReading {
        cpu: file("/proc/stat").as_deref().and_then(parse_proc_stat),
        load1: file("/proc/loadavg").as_deref().and_then(parse_loadavg),
        nics: file("/proc/net/dev")
            .map(|s| parse_net_dev(&s))
            .unwrap_or_default(),
        gateways,
        dns_servers,
    }
}

/// The aggregate `cpu` line of `/proc/stat`: user nice system idle iowait
/// irq softirq steal (guest time is already in user and nice).
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat(s: &str) -> Option<CpuTimes> {
    let line = s.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_ascii_whitespace()
        .skip(1)
        .take(8)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if v.len() < 4 {
        return None;
    }
    let total: u64 = v.iter().sum();
    let idle = v[3] + v.get(4).copied().unwrap_or(0);
    Some(CpuTimes {
        busy: total - idle,
        total,
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_loadavg(s: &str) -> Option<f64> {
    s.split_ascii_whitespace().next()?.parse().ok()
}

/// `/proc/net/dev`: two header lines, then `name: rx(8 fields) tx(8 fields)`.
#[cfg(any(target_os = "linux", test))]
fn parse_net_dev(s: &str) -> Vec<NicCounters> {
    s.lines()
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let name = name.trim();
            if name == "lo" {
                return None;
            }
            let f: Vec<u64> = rest
                .split_ascii_whitespace()
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?;
            if f.len() < 12 {
                return None;
            }
            Some(NicCounters {
                name: name.to_string(),
                rx_errors: f[2],
                rx_drops: f[3],
                tx_errors: f[10],
                tx_drops: f[11],
            })
        })
        .collect()
}

/// IPv4 default routes from `/proc/net/route`: destination and mask 0, the
/// gateway flag set, addresses in hex as stored in memory (network order
/// read as a little-endian word).
#[cfg(any(target_os = "linux", test))]
fn parse_route(s: &str) -> Vec<IpAddr> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    s.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_ascii_whitespace().collect();
            if f.len() < 8 {
                return None;
            }
            let hex = |i: usize| u32::from_str_radix(f[i], 16).ok();
            let (dest, gw, flags, mask) = (hex(1)?, hex(2)?, hex(3)?, hex(7)?);
            let wanted = RTF_UP | RTF_GATEWAY;
            (dest == 0 && mask == 0 && flags & wanted == wanted && gw != 0)
                .then(|| IpAddr::V4(Ipv4Addr::from(gw.to_le_bytes())))
        })
        .collect()
}

/// IPv6 default routes from `/proc/net/ipv6_route`: destination `::/0`
/// with a next hop, not on `lo` (where the kernel keeps its unreachable
/// default).
#[cfg(any(target_os = "linux", test))]
fn parse_ipv6_route(s: &str) -> Vec<IpAddr> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_ascii_whitespace().collect();
            if f.len() < 10 || f[9] == "lo" || f[1] != "00" {
                return None;
            }
            let dest = u128::from_str_radix(f[0], 16).ok()?;
            let hop = u128::from_str_radix(f[4], 16).ok()?;
            (dest == 0 && hop != 0).then(|| IpAddr::V6(Ipv6Addr::from(hop)))
        })
        .collect()
}

/// `nameserver` lines of a `resolv.conf`; an IPv6 zone (`%eth0`) is dropped.
#[cfg(any(target_os = "linux", test))]
fn parse_resolv_conf(s: &str) -> Vec<IpAddr> {
    s.lines()
        .filter_map(|l| {
            let mut it = l.split_ascii_whitespace();
            if it.next()? != "nameserver" {
                return None;
            }
            let addr = it.next()?;
            let addr = addr.split_once('%').map_or(addr, |(a, _)| a);
            addr.parse().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_times_count_iowait_as_idle() {
        let s = "cpu  100 5 50 800 20 3 2 1 0 0\ncpu0 1 2 3 4 5 6 7 8 0 0\nintr 1\n";
        assert_eq!(
            parse_proc_stat(s),
            Some(CpuTimes {
                busy: 161,
                total: 981
            })
        );
        assert_eq!(parse_proc_stat("intr 1\n"), None);
        assert_eq!(parse_loadavg("0.52 0.40 0.31 1/123 4567\n"), Some(0.52));
    }

    #[test]
    fn net_dev_skips_loopback_and_reads_errors_and_drops() {
        let s = "Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 123456 789 4 7 0 0 0 12 654321 987 1 2 0 0 0 0
";
        assert_eq!(
            parse_net_dev(s),
            vec![NicCounters {
                name: "eth0".into(),
                rx_errors: 4,
                rx_drops: 7,
                tx_errors: 1,
                tx_drops: 2,
            }]
        );
    }

    #[test]
    fn default_routes_are_found_for_both_families() {
        let v4 =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
";
        assert_eq!(
            parse_route(v4),
            vec!["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        let v6 = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0
";
        assert_eq!(
            parse_ipv6_route(v6),
            vec!["fe80::1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn resolv_conf_nameservers_in_order() {
        let s = "# comment\nsearch example.org\nnameserver 192.0.2.53\nnameserver fe80::1%eth0\nnameserver bogus\noptions edns0\n";
        let want: Vec<IpAddr> = vec!["192.0.2.53".parse().unwrap(), "fe80::1".parse().unwrap()];
        assert_eq!(parse_resolv_conf(s), want);
    }

    #[test]
    fn duplicates_are_dropped_keeping_order() {
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let mut v = vec![a, b, a, b];
        dedup(&mut v);
        assert_eq!(v, vec![a, b]);
    }

    #[test]
    fn reading_this_host_does_not_fail() {
        let r = read();
        if cfg!(any(target_os = "linux", windows)) {
            let cpu = r.cpu.expect("CPU times");
            assert!(cpu.busy <= cpu.total && cpu.total > 0);
        }
    }
}
