//! The local health snapshot sampler (architecture doc §19, §21.3 E13):
//! once a minute, on the minute, read this machine's CPU, NIC counters,
//! default gateways and DNS servers, store the sample in the health log
//! and keep it for `/metrics`.
//!
//! It runs on its own thread: the readings block (file reads, IP Helper
//! calls) and must not hold up the probes or the store.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use rl_store::{HealthLog, HealthSample, NicDelta};
use rl_sys::host::{HostReading, NicCounters};
use rl_web::{HostHealth, LatestHost, NicTotal};

const MINUTE_MS: i64 = 60_000;
/// Days of health samples kept: the raw tier's retention.
pub(crate) const KEEP_DAYS: i64 = 30;

/// Start sampling; it stops when `stop`'s sender is dropped.
pub(crate) fn spawn(
    data_dir: PathBuf,
    vantage: String,
    latest: Arc<LatestHost>,
    stop: Receiver<()>,
    now_ms: fn() -> i64,
) -> std::io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("health".into())
        .spawn(move || run(&data_dir, &vantage, &latest, &stop, now_ms))
}

fn run(
    data_dir: &std::path::Path,
    vantage: &str,
    latest: &LatestHost,
    stop: &Receiver<()>,
    now_ms: fn() -> i64,
) {
    let mut log: Option<HealthLog> = None;
    // One message per change between storing and not storing.
    let mut failing = false;
    let mut prev: Option<(HostReading, i64)> = None;
    loop {
        let t = now_ms();
        let cur = rl_sys::host::read();
        let s = sample(prev.as_ref().map(|(r, t)| (r, *t)), &cur, t);
        // Opened (again) each minute until it works: a full disk or a
        // permission fixed later lets history resume without a restart.
        if log.is_none() {
            match HealthLog::open(data_dir, vantage, KEEP_DAYS) {
                Ok(l) => log = Some(l),
                Err(e) if !failing => {
                    eprintln!("routelith server: cannot store health snapshots: {e}");
                    failing = true;
                }
                Err(_) => {}
            }
        }
        if let Some(log) = &mut log {
            match log.append(&s) {
                Ok(()) if failing => {
                    eprintln!("routelith server: health snapshots are stored again");
                    failing = false;
                }
                Ok(()) => {}
                Err(e) if !failing => {
                    eprintln!("routelith server: cannot store a health snapshot: {e}");
                    failing = true;
                }
                Err(_) => {}
            }
        }
        latest.record(HostHealth {
            sample: s,
            nics: cur.nics.iter().flatten().map(total).collect(),
        });
        prev = Some((baseline(prev.map(|(r, _)| r), cur), t));
        // Sleep to the next whole minute (UTC), so samples line up across
        // machines and restarts.
        let wait = MINUTE_MS - now_ms().rem_euclid(MINUTE_MS);
        let wait = Duration::from_millis(u64::try_from(wait).unwrap_or(0).max(1));
        match stop.recv_timeout(wait) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn total(n: &NicCounters) -> NicTotal {
    NicTotal {
        name: n.name.clone(),
        rx_errors: n.rx_errors,
        tx_errors: n.tx_errors,
        rx_drops: n.rx_drops,
        tx_drops: n.tx_drops,
    }
}

/// Growth of a counter; after a reset (the interface came back up) the
/// new value is all growth.
fn grew(prev: u64, cur: u64) -> u64 {
    if cur >= prev { cur - prev } else { cur }
}

/// The reading the next sample counts from: `cur`, but with the last
/// NIC counters that could be read when `cur` has none, so growth while
/// they were unreadable shows up once they are back.
fn baseline(prev: Option<HostReading>, mut cur: HostReading) -> HostReading {
    if cur.nics.is_none() {
        cur.nics = prev.and_then(|p| p.nics);
    }
    cur
}

/// The sample for the interval from `prev` to `cur` at `t`. Without a
/// previous reading only the gateways, DNS servers and load are known.
pub(crate) fn sample(prev: Option<(&HostReading, i64)>, cur: &HostReading, t: i64) -> HealthSample {
    let mut s = HealthSample {
        t,
        load1: cur.load1.map(|l| (l * 100.0).round() / 100.0),
        gateways: cur.gateways.clone(),
        dns: cur.dns_servers.clone(),
        ..HealthSample::default()
    };
    let Some((prev, prev_t)) = prev else {
        return s;
    };
    s.interval_ms = t - prev_t;
    if let (Some(a), Some(b)) = (prev.cpu, cur.cpu) {
        let total = b.total.saturating_sub(a.total);
        if total > 0 && b.busy >= a.busy {
            let busy = (b.busy - a.busy).min(total);
            let pct = busy as f64 * 100.0 / total as f64;
            s.cpu_pct = Some((pct * 10.0).round() / 10.0);
        }
    }
    // Unknown, not zero, while the counters cannot be read (now or at the
    // baseline).
    let (Some(prev_nics), Some(cur_nics)) = (&prev.nics, &cur.nics) else {
        return s;
    };
    let (mut errors, mut drops) = (0, 0);
    for n in cur_nics {
        // An interface that just appeared has no baseline yet.
        let Some(p) = prev_nics.iter().find(|p| p.name == n.name) else {
            continue;
        };
        let e = grew(p.rx_errors, n.rx_errors) + grew(p.tx_errors, n.tx_errors);
        let d = grew(p.rx_drops, n.rx_drops) + grew(p.tx_drops, n.tx_drops);
        errors += e;
        drops += d;
        if e > 0 || d > 0 {
            s.nics.push(NicDelta {
                name: n.name.clone(),
                errors: e,
                drops: d,
            });
        }
    }
    s.nic_errors = Some(errors);
    s.nic_drops = Some(drops);
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_sys::host::CpuTimes;

    fn nic(name: &str, rx_errors: u64, rx_drops: u64) -> NicCounters {
        NicCounters {
            name: name.into(),
            rx_errors,
            rx_drops,
            ..NicCounters::default()
        }
    }

    fn reading(busy: u64, total: u64, nics: Vec<NicCounters>, gw: &str) -> HostReading {
        HostReading {
            cpu: Some(CpuTimes { busy, total }),
            load1: Some(0.75),
            nics: Some(nics),
            gateways: vec![gw.parse().unwrap()],
            dns_servers: vec!["192.0.2.53".parse().unwrap()],
        }
    }

    #[test]
    fn the_first_sample_has_no_counters() {
        let r = reading(10, 100, vec![nic("eth0", 5, 5)], "192.0.2.1");
        let s = sample(None, &r, 60_000);
        assert_eq!((s.interval_ms, s.cpu_pct, s.nic_errors), (0, None, None));
        assert_eq!(s.load1, Some(0.75));
        assert_eq!(s.gateways[0].to_string(), "192.0.2.1");
    }

    #[test]
    fn deltas_cover_the_interval() {
        let a = reading(
            100,
            1000,
            vec![nic("eth0", 5, 10), nic("wlan0", 7, 0)],
            "192.0.2.1",
        );
        let b = reading(
            400,
            2000,
            // wlan0 was reset; usb0 is new.
            vec![nic("eth0", 6, 13), nic("usb0", 50, 50), nic("wlan0", 2, 0)],
            "192.0.2.254",
        );
        let s = sample(Some((&a, 0)), &b, 60_000);
        assert_eq!(s.interval_ms, 60_000);
        assert_eq!(s.cpu_pct, Some(30.0));
        assert_eq!((s.nic_errors, s.nic_drops), (Some(3), Some(3)));
        assert_eq!(
            s.nics,
            vec![
                NicDelta {
                    name: "eth0".into(),
                    errors: 1,
                    drops: 3
                },
                NicDelta {
                    name: "wlan0".into(),
                    errors: 2,
                    drops: 0
                },
            ]
        );
        assert_eq!(s.gateways[0].to_string(), "192.0.2.254");
    }

    #[test]
    fn unreadable_nic_counters_are_unknown_and_keep_the_baseline() {
        let a = reading(0, 100, vec![nic("eth0", 5, 0)], "192.0.2.1");
        let mut gone = reading(10, 200, Vec::new(), "192.0.2.1");
        gone.nics = None;
        let s = sample(Some((&a, 0)), &gone, 60_000);
        assert_eq!((s.nic_errors, s.nic_drops), (None, None));
        assert_eq!(s.cpu_pct, Some(10.0));
        // Back: the ten errors since the last good reading are counted.
        let base = baseline(Some(a), gone);
        let c = reading(20, 300, vec![nic("eth0", 15, 0)], "192.0.2.1");
        let s = sample(Some((&base, 60_000)), &c, 120_000);
        assert_eq!(s.nic_errors, Some(10));
    }

    #[test]
    fn the_sampler_stores_a_snapshot_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let latest = Arc::new(LatestHost::default());
        let (tx, rx) = std::sync::mpsc::channel();
        fn now() -> i64 {
            1_800_000_000_000
        }
        let h = spawn(dir.path().into(), "local".into(), latest.clone(), rx, now).unwrap();
        // The first sample is taken at once; wait for it, then stop.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while latest.get().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(tx);
        h.join().unwrap();
        let got = latest.get().expect("a snapshot");
        assert_eq!(got.sample.t, now());
        let stored = rl_store::read_health(dir.path(), "local", now(), now() + 1).unwrap();
        assert_eq!(stored, vec![got.sample]);
    }
}
