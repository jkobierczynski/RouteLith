//! Sweeps to loopback through the real OS backend (Linux ping socket and
//! error queue, the Windows ICMP API on its APC thread). Loopback is one hop
//! away, so every probe gets an echo reply from the destination.
//!
//! On Linux the test user's group must be in `net.ipv4.ping_group_range`
//! (CI sets it). The multi-hop checks are in `tests/lab/trace-lab.sh`.
#![cfg(any(target_os = "linux", windows))]

use std::net::IpAddr;
use std::time::Duration;

use rl_path::{Outcome, Session, SweepPlan, TraceError, TraceStats};

fn plan() -> SweepPlan {
    SweepPlan {
        interval: Duration::from_millis(100),
        max_ttl: 4,
        timeout: Duration::from_secs(1),
    }
}

async fn sweeps_to(addr: &str) -> Result<(), TraceError> {
    let dest: IpAddr = addr.parse().unwrap();
    let tracer = rl_path::open(dest)?;
    let mut session = Session::new(plan());
    let mut stats = TraceStats::new();
    for _ in 0..5 {
        let sweep = rl_path::run_sweep(tracer.clone(), session.next_count(), plan()).await;
        for hop in &sweep.hops {
            match hop {
                Outcome::Reply { from, rtt } => {
                    assert_eq!(*from, dest);
                    assert!(*rtt < Duration::from_millis(50), "{rtt:?}");
                }
                other => panic!("loopback answered {other:?}"),
            }
        }
        session.record(&sweep);
        stats.add(&sweep);
    }
    // The first sweep probes TTL 1 to 4; once the destination is known at
    // TTL 1, the others probe only that.
    assert_eq!(session.next_count(), 1);
    let hops = stats.hops();
    assert_eq!(hops.len(), 1);
    assert_eq!((hops[0].sent, hops[0].received), (5, 5));
    assert!(hops[0].is_dest);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ipv4_loopback_sweeps() {
    sweeps_to("127.0.0.1").await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn ipv6_loopback_sweeps() {
    match sweeps_to("::1").await {
        Ok(()) => {}
        // Containers without IPv6 cannot open an ICMPv6 socket at all.
        Err(TraceError::Probe(rl_probe::ProbeError::Io(e)) | TraceError::Io(e))
            if e.raw_os_error() == Some(97)
                || cfg!(windows) && e.to_string().contains("family") =>
        {
            eprintln!("skipped: IPv6 is not available on this host ({e})");
        }
        Err(e) => panic!("{e}"),
    }
}
