//! Sweeps: one probe per TTL, spread over the interval (§21.9 P4).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rl_core::TimingBackend;

use crate::{Outcome, Tracer};

/// How a trace probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepPlan {
    /// Time between sweep starts; a sweep's probes are spread over it.
    pub interval: Duration,
    /// Highest TTL probed while the destination's distance is unknown.
    pub max_ttl: u8,
    /// How long each probe waits for an answer.
    pub timeout: Duration,
}

impl Default for SweepPlan {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(2500),
            max_ttl: 30,
            timeout: Duration::from_secs(2),
        }
    }
}

/// One sweep: the outcome for TTL 1, 2, … in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sweep {
    pub start: SystemTime,
    /// `hops[i]` is TTL `i + 1`.
    pub hops: Vec<Outcome>,
    pub timing: TimingBackend,
}

impl Sweep {
    /// The lowest TTL whose answer ends the path (echo reply or Unreachable).
    pub fn dest_ttl(&self) -> Option<u8> {
        self.hops
            .iter()
            .position(Outcome::ends_path)
            .and_then(|i| u8::try_from(i + 1).ok())
    }
}

/// Decides how many TTLs each sweep probes. Once the destination answers at
/// TTL d, sweeps stop at d; if a router answers at d instead (the path got
/// longer), the next sweep probes up to `max_ttl` again. A lost probe at d
/// changes nothing.
#[derive(Debug, Clone)]
pub struct Session {
    plan: SweepPlan,
    dest_ttl: Option<u8>,
    /// Start of the newest sweep recorded; sweeps overlap and can finish
    /// out of order, and an older one must not undo a newer one.
    last_start: Option<SystemTime>,
}

impl Session {
    pub fn new(plan: SweepPlan) -> Self {
        Self {
            plan,
            dest_ttl: None,
            last_start: None,
        }
    }

    pub fn plan(&self) -> SweepPlan {
        self.plan
    }

    /// TTLs the next sweep probes: 1 to this.
    pub fn next_count(&self) -> u8 {
        self.dest_ttl
            .unwrap_or(self.plan.max_ttl)
            .clamp(1, self.plan.max_ttl.max(1))
    }

    /// Distance of the destination as last seen.
    pub fn dest_ttl(&self) -> Option<u8> {
        self.dest_ttl
    }

    /// Update the plan from a finished sweep.
    pub fn record(&mut self, sweep: &Sweep) {
        if self.last_start.is_some_and(|last| sweep.start < last) {
            return;
        }
        self.last_start = Some(sweep.start);
        if let Some(d) = sweep.dest_ttl() {
            self.dest_ttl = Some(d);
        } else if let Some(d) = self.dest_ttl {
            let last = sweep.hops.get(usize::from(d) - 1);
            if matches!(last, Some(Outcome::TimeExceeded { .. })) {
                self.dest_ttl = None;
            }
        }
    }
}

/// Run one sweep of TTL 1 to `count`. Probe `i` leaves `i × interval /
/// count` after the start; the sweep ends when the last probe has its
/// answer or timed out, so consecutive sweeps overlap.
pub async fn run_sweep(tracer: Arc<dyn Tracer>, count: u8, plan: SweepPlan) -> Sweep {
    let start = SystemTime::now();
    let t0 = tokio::time::Instant::now();
    let n = u32::from(count.max(1));
    let mut tasks = Vec::with_capacity(count as usize);
    for i in 0..n {
        let tracer = Arc::clone(&tracer);
        let at = t0 + plan.interval * i / n;
        let ttl = u8::try_from(i + 1).unwrap_or(u8::MAX);
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep_until(at).await;
            tracer.probe(ttl, plan.timeout).await
        }));
    }
    let mut hops = Vec::with_capacity(tasks.len());
    let mut timing = tracer.timing();
    for task in tasks {
        match task.await {
            Ok(r) => {
                // A fallback anywhere in the sweep marks the sweep.
                if r.timing != tracer.timing() {
                    timing = r.timing;
                }
                hops.push(r.outcome);
            }
            Err(e) => hops.push(Outcome::SendFailed(e.to_string())),
        }
    }
    Sweep {
        start,
        hops,
        timing,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    use super::*;
    use crate::{BoxFuture, ProbeResult};

    const MS: Duration = Duration::from_millis(1);

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn sweep(hops: Vec<Outcome>) -> Sweep {
        Sweep {
            start: SystemTime::UNIX_EPOCH,
            hops,
            timing: TimingBackend::LinuxMonotonic,
        }
    }

    fn te(n: u8) -> Outcome {
        Outcome::TimeExceeded {
            from: ip(n),
            rtt: MS,
        }
    }

    fn reply() -> Outcome {
        Outcome::Reply {
            from: ip(100),
            rtt: MS,
        }
    }

    #[test]
    fn session_stops_at_the_destination_and_widens_when_the_path_grows() {
        let plan = SweepPlan {
            max_ttl: 10,
            ..SweepPlan::default()
        };
        let mut s = Session::new(plan);
        assert_eq!(s.next_count(), 10);
        s.record(&sweep(vec![te(1), te(2), reply(), reply(), reply()]));
        assert_eq!(s.next_count(), 3);
        // A lost probe at the destination's TTL changes nothing.
        s.record(&sweep(vec![te(1), te(2), Outcome::Lost]));
        assert_eq!(s.next_count(), 3);
        // Shorter path: the destination answers earlier.
        s.record(&sweep(vec![te(1), reply(), reply()]));
        assert_eq!(s.next_count(), 2);
        // Longer path: a router answers at the old distance.
        s.record(&sweep(vec![te(1), te(2)]));
        assert_eq!(s.next_count(), 10);
    }

    #[test]
    fn an_older_sweep_finishing_late_is_ignored() {
        let mut s = Session::new(SweepPlan::default());
        let mut newer = sweep(vec![te(1), reply()]);
        newer.start = SystemTime::UNIX_EPOCH + Duration::from_secs(2);
        let mut older = sweep(vec![reply()]);
        older.start = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        s.record(&newer);
        s.record(&older);
        assert_eq!(s.next_count(), 2);
    }

    #[test]
    fn unreachable_ends_the_path() {
        let unreach = Outcome::Unreachable {
            from: Some(ip(2)),
            code: 1,
            rtt: MS,
        };
        assert_eq!(
            sweep(vec![te(1), unreach, Outcome::Lost]).dest_ttl(),
            Some(2)
        );
        assert_eq!(sweep(vec![te(1), Outcome::Lost]).dest_ttl(), None);
    }

    /// Answers like a 3-hop path and records when each probe left.
    #[derive(Debug)]
    struct Fake {
        sent: Mutex<Vec<(u8, tokio::time::Instant)>>,
    }

    impl Tracer for Fake {
        fn dest(&self) -> IpAddr {
            ip(100)
        }
        fn timing(&self) -> TimingBackend {
            TimingBackend::LinuxKernelTimestamp
        }
        fn probe(&self, ttl: u8, _timeout: Duration) -> BoxFuture<'_, ProbeResult> {
            self.sent
                .lock()
                .unwrap()
                .push((ttl, tokio::time::Instant::now()));
            Box::pin(async move {
                ProbeResult {
                    outcome: if ttl < 3 { te(ttl) } else { reply() },
                    timing: TimingBackend::LinuxKernelTimestamp,
                }
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn probes_are_spread_over_the_interval_in_ttl_order() {
        let fake = Arc::new(Fake {
            sent: Mutex::new(Vec::new()),
        });
        let plan = SweepPlan {
            interval: Duration::from_millis(1000),
            max_ttl: 4,
            timeout: Duration::from_secs(1),
        };
        let t0 = tokio::time::Instant::now();
        let s = run_sweep(fake.clone(), 4, plan).await;
        assert_eq!(s.hops, vec![te(1), te(2), reply(), reply()]);
        assert_eq!(s.dest_ttl(), Some(3));
        let mut sent = fake.sent.lock().unwrap().clone();
        sent.sort_by_key(|&(ttl, _)| ttl);
        let offsets: Vec<u128> = sent.iter().map(|&(_, t)| (t - t0).as_millis()).collect();
        assert_eq!(offsets, vec![0, 250, 500, 750]);
    }
}
