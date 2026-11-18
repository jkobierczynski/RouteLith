//! Loopback rounds against the real OS backend (Linux ping socket, Windows ICMP API).
//!
//! On Linux the test user's group must be in `net.ipv4.ping_group_range`
//! (CI sets it). Other platforms have no ICMP backend yet.
#![cfg(any(target_os = "linux", windows))]

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use rl_core::{ResolvedTarget, RoundPlan, RoundStats, TimingBackend};
use rl_probe::{IcmpProbe, Probe, ProbeError};

fn plan(count: u16, spread_ms: u64) -> RoundPlan {
    RoundPlan {
        count,
        spread: Duration::from_millis(spread_ms),
        timeout: Duration::from_secs(1),
        round_start: SystemTime::now(),
    }
}

fn target(addr: &str) -> ResolvedTarget {
    ResolvedTarget {
        name: addr.to_owned(),
        addr: addr.parse::<IpAddr>().unwrap(),
    }
}

fn expected_backends() -> &'static [TimingBackend] {
    if cfg!(windows) {
        &[TimingBackend::WindowsIcmpApi]
    } else {
        &[
            TimingBackend::LinuxKernelTimestamp,
            TimingBackend::LinuxMonotonic,
        ]
    }
}

async fn assert_clean_round(probe: &IcmpProbe, addr: &str) -> Result<(), ProbeError> {
    let t = target(addr);
    let round = probe.run_round(&t, plan(10, 200)).await?;
    let stats = RoundStats::from_samples(&round.samples);
    assert_eq!(round.samples.len(), 10);
    assert_eq!(
        stats.received, 10,
        "loopback lost samples: {:?}",
        round.samples
    );
    assert!(
        stats.max_us.unwrap() < 50_000,
        "loopback RTT over 50 ms: {stats:?}"
    );
    assert_eq!(round.meta.resolved, t.addr);
    assert!(expected_backends().contains(&round.meta.timing.backend));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ipv4_loopback_round() {
    let probe = IcmpProbe::default();
    assert_clean_round(&probe, "127.0.0.1").await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn ipv6_loopback_round() {
    let probe = IcmpProbe::default();
    match assert_clean_round(&probe, "::1").await {
        Ok(()) => {}
        // Containers without IPv6 cannot open an ICMPv6 socket at all.
        Err(ProbeError::Io(e)) if e.raw_os_error() == Some(97) => {
            eprintln!("skipped: IPv6 is not available on this host ({e})");
        }
        Err(e) => panic!("{e}"),
    }
}

/// Two targets share one socket; every reply must reach the right round.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_rounds_share_one_socket() {
    let probe = IcmpProbe::default();
    let (a, b) = (target("127.0.0.1"), target("127.0.0.2"));
    let (ra, rb) = tokio::join!(
        probe.run_round(&a, plan(50, 100)),
        probe.run_round(&b, plan(50, 100))
    );
    for round in [ra.unwrap(), rb.unwrap()] {
        let stats = RoundStats::from_samples(&round.samples);
        assert_eq!(
            stats.received, 50,
            "{}: {:?}",
            round.meta.resolved, round.samples
        );
    }
}
