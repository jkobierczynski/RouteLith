//! Trace jobs (architecture doc §21.9 P4–P6): sweeps every
//! `trace_interval`, and every `trace_step` one round per TTL for the hop
//! series.
//!
//! Steps are aligned like a target's rounds (`k × step + offset`). Each
//! step's sweeps run in a task of their own, so the last sweep of a step
//! can still wait for its answers while the next step starts; the
//! [`Session`] that decides how far each sweep probes is shared by all.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use rl_core::config::{Family, TRACE_TIMEOUT, TraceConfig};
use rl_core::{ProbeMeta, RoundResult, Sample, SampleError, TimingSource};
use rl_path::{Outcome as Hop, Session, Sweep, SweepPlan, Tracer};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::{Completed, MAX_SLEEP, Outcome, RESOLVE_TIMEOUT, Sink, next_slot, phase_offset};
use crate::{resolve, system_time, wall_us};

/// One traced target and family.
#[derive(Debug, Clone)]
pub struct TraceJob {
    /// Hop series ids: `hop_series[i]` is TTL `i + 1`, one per TTL up to
    /// `cfg.max_ttl`.
    pub hop_series: Vec<u64>,
    /// Series id the raw sweeps are kept under.
    pub raw_series: u64,
    pub vantage: String,
    pub target: String,
    pub host: String,
    /// `V4`, `V6` or `PreferV6`.
    pub family: Family,
    /// For `PreferV6`: whether IPv6 may be used.
    pub v6_usable: bool,
    pub cfg: TraceConfig,
}

impl TraceJob {
    /// Offset of this trace's steps; differs from the target's own rounds.
    pub fn offset(&self) -> Duration {
        phase_offset(
            &[&self.vantage, &self.target, self.family.as_str(), "trace"],
            self.cfg.step,
        )
    }

    fn label(&self) -> String {
        format!("{}/{} trace", self.target, self.family.as_str())
    }
}

/// Where each finished sweep goes, with the job's raw series id. Returns
/// `false` if it was dropped.
pub type SweepSink = Arc<dyn Fn(u64, Sweep) -> bool + Send + Sync>;

/// Opens a tracer for an address (normally [`rl_path::open`]).
pub type OpenTracer = Arc<dyn Fn(IpAddr) -> Result<Arc<dyn Tracer>, String> + Send + Sync>;

/// The rounds of one step: per TTL that any sweep probed up to where its
/// path ended, a round whose samples are that TTL's answers in sweep
/// order. A router's Time Exceeded and the destination's reply both count
/// as replies; probes past the end of the path (the destination answers
/// those too) are left out.
pub fn hop_rounds(start: SystemTime, dest: IpAddr, sweeps: &[Sweep]) -> Vec<(u8, RoundResult)> {
    let path = |s: &Sweep| s.dest_ttl().map_or(s.hops.len(), usize::from);
    let deepest = sweeps.iter().map(path).max().unwrap_or(0);
    // A fallback in any sweep marks the step's rounds.
    let timing = sweeps
        .iter()
        .map(|s| s.timing)
        .find(|t| Some(*t) != sweeps.first().map(|s| s.timing))
        .or_else(|| sweeps.first().map(|s| s.timing));
    let Some(timing) = timing else {
        return Vec::new();
    };
    (1..=deepest)
        .filter_map(|ttl| {
            let samples: Vec<Sample> = sweeps
                .iter()
                .filter(|s| path(s) >= ttl)
                .filter_map(|s| s.hops.get(ttl - 1))
                .map(sample)
                .collect();
            let ttl = u8::try_from(ttl).ok()?;
            Some((
                ttl,
                RoundResult {
                    start,
                    samples,
                    meta: ProbeMeta {
                        resolved: dest,
                        timing: TimingSource::new(timing),
                        payload_size: u16::try_from(rl_path::PAYLOAD_SIZE).unwrap_or(u16::MAX),
                    },
                    http: None,
                },
            ))
        })
        .collect()
}

fn sample(hop: &Hop) -> Sample {
    let us = |d: Duration| u32::try_from(d.as_micros()).unwrap_or(u32::MAX);
    match hop {
        Hop::TimeExceeded { rtt, .. } | Hop::Reply { rtt, .. } => Sample::Ok { rtt_us: us(*rtt) },
        Hop::Unreachable { code, .. } => Sample::Error(SampleError::Unreachable { code: *code }),
        Hop::Lost => Sample::Lost,
        Hop::SendFailed(e) => Sample::Error(SampleError::SendFailed(e.clone())),
    }
}

/// Run one step's `n` sweeps, sweep `i` starting `i × interval` after now.
/// Each sweep goes to `sweeps` as it finishes; returns them in start order.
pub async fn run_step(
    tracer: Arc<dyn Tracer>,
    session: Arc<Mutex<Session>>,
    n: u32,
    on_sweep: impl Fn(Sweep) + Send + Sync + 'static,
) -> Vec<Sweep> {
    let plan = session
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .plan();
    let on_sweep = Arc::new(on_sweep);
    let t0 = Instant::now();
    let mut tasks = Vec::with_capacity(n as usize);
    for i in 0..n {
        let (tracer, session, on_sweep) = (
            Arc::clone(&tracer),
            Arc::clone(&session),
            Arc::clone(&on_sweep),
        );
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep_until(t0 + plan.interval * i).await;
            let count = session
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .next_count();
            let sweep = rl_path::run_sweep(tracer, count, plan).await;
            session
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .record(&sweep);
            on_sweep(sweep.clone());
            sweep
        }));
    }
    let mut out = Vec::with_capacity(tasks.len());
    for t in tasks {
        if let Ok(s) = t.await {
            out.push(s);
        }
    }
    out
}

/// Run one trace until `shutdown` turns true.
pub async fn run_trace(
    job: TraceJob,
    open: OpenTracer,
    sink: Sink,
    sweeps: SweepSink,
    mut shutdown: watch::Receiver<bool>,
) {
    let step = job.cfg.step;
    let step_us = i64::try_from(step.as_micros()).unwrap_or(i64::MAX);
    let offset = job.offset();
    let n = job.cfg.sweeps_per_step();
    let session = Arc::new(Mutex::new(Session::new(SweepPlan {
        interval: job.cfg.interval,
        max_ttl: job.cfg.max_ttl,
        timeout: TRACE_TIMEOUT,
    })));
    let family = if job.family == Family::PreferV6 && !job.v6_usable {
        Family::V4
    } else {
        job.family
    };
    let mut tracer: Option<Arc<dyn Tracer>> = None;
    let mut last_error: Option<String> = None;
    let mut steps = JoinSet::new();
    let mut slot = next_slot(wall_us(), step, offset);
    loop {
        loop {
            if *shutdown.borrow() {
                return;
            }
            // Reap finished steps so the set stays small.
            while steps.try_join_next().is_some() {}
            let left = slot - wall_us();
            if left <= 0 {
                break;
            }
            let nap = Duration::from_micros(left.unsigned_abs()).min(MAX_SLEEP);
            tokio::select! {
                () = tokio::time::sleep(nap) => {}
                _ = shutdown.wait_for(|&stop| stop) => return,
            }
        }
        let now = wall_us();
        if now - slot > step_us {
            slot = next_slot(now, step, offset);
            continue;
        }
        let start = system_time(slot);
        slot += step_us;

        let addr = tokio::select! {
            r = tokio::time::timeout(RESOLVE_TIMEOUT.min(step), resolve(&job.host, family)) => {
                r.unwrap_or_else(|_| Err("lookup timed out".into()))
            }
            _ = shutdown.wait_for(|&stop| stop) => return,
        };
        let opened = addr
            .map_err(|e| format!("cannot resolve {}: {e}", job.host))
            .and_then(|addr| match &tracer {
                Some(t) if t.dest() == addr => Ok(Arc::clone(t)),
                _ => open(addr).map_err(|e| format!("cannot trace {addr}: {e}")),
            });
        let t = match opened {
            Ok(t) => t,
            Err(e) => {
                if last_error.as_deref() != Some(&e) {
                    eprintln!("routelith server: {}: {e}", job.label());
                    last_error = Some(e);
                }
                continue;
            }
        };
        if last_error.take().is_some() {
            eprintln!("routelith server: {}: tracing again", job.label());
        }
        if tracer.as_ref().is_some_and(|old| old.dest() != t.dest()) {
            // A new address is a new path: learn its length again.
            let plan = session
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .plan();
            *session.lock().unwrap_or_else(PoisonError::into_inner) = Session::new(plan);
        }
        tracer = Some(Arc::clone(&t));
        let (session, sink, sweeps, job) = (
            Arc::clone(&session),
            Arc::clone(&sink),
            Arc::clone(&sweeps),
            job.clone(),
        );
        steps.spawn(async move {
            let raw = job.raw_series;
            let dest = t.dest();
            let done = run_step(t, session, n, move |s| {
                let _ = sweeps(raw, s);
            })
            .await;
            for (ttl, round) in hop_rounds(start, dest, &done) {
                if let Some(&series) = job.hop_series.get(usize::from(ttl) - 1) {
                    let _ = sink(Completed {
                        series,
                        outcome: Outcome::Measured(round),
                        flags: 0,
                    });
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rl_core::TimingBackend;
    use rl_path::{BoxFuture, ProbeResult};

    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    fn sweep(hops: Vec<Hop>) -> Sweep {
        Sweep {
            start: SystemTime::UNIX_EPOCH,
            hops,
            timing: TimingBackend::LinuxKernelTimestamp,
        }
    }

    #[test]
    fn one_round_per_probed_ttl() {
        let te = |n| Hop::TimeExceeded {
            from: ip(n),
            rtt: MS * u32::from(n),
        };
        let reply = Hop::Reply {
            from: ip(100),
            rtt: MS * 3,
        };
        let sweeps = vec![
            sweep(vec![te(1), te(2), reply.clone(), reply.clone()]),
            sweep(vec![te(1), Hop::Lost, reply.clone()]),
            sweep(vec![
                Hop::SendFailed("x".into()),
                te(2),
                Hop::Unreachable {
                    from: Some(ip(3)),
                    code: 1,
                    rtt: MS,
                },
            ]),
        ];
        let rounds = hop_rounds(SystemTime::UNIX_EPOCH, ip(100), &sweeps);
        // The second reply of the first sweep is past the destination.
        assert_eq!(rounds.len(), 3);
        let samples = |i: usize| rounds[i].1.samples.clone();
        assert_eq!(rounds[0].0, 1);
        assert_eq!(
            samples(0),
            vec![
                Sample::Ok { rtt_us: 1000 },
                Sample::Ok { rtt_us: 1000 },
                Sample::Error(SampleError::SendFailed("x".into()))
            ]
        );
        assert_eq!(samples(1)[1], Sample::Lost);
        assert_eq!(
            samples(2)[2],
            Sample::Error(SampleError::Unreachable { code: 1 })
        );
        assert_eq!(rounds[0].1.meta.resolved, ip(100));
    }

    #[test]
    fn no_sweeps_no_rounds() {
        assert!(hop_rounds(SystemTime::UNIX_EPOCH, ip(1), &[]).is_empty());
    }

    /// A 3-hop path.
    #[derive(Debug)]
    struct Fake;

    impl Tracer for Fake {
        fn dest(&self) -> IpAddr {
            ip(100)
        }
        fn timing(&self) -> TimingBackend {
            TimingBackend::LinuxKernelTimestamp
        }
        fn probe(&self, ttl: u8, _timeout: Duration) -> BoxFuture<'_, ProbeResult> {
            Box::pin(async move {
                ProbeResult {
                    outcome: if ttl < 3 {
                        Hop::TimeExceeded {
                            from: ip(ttl),
                            rtt: MS,
                        }
                    } else {
                        Hop::Reply {
                            from: ip(100),
                            rtt: MS,
                        }
                    },
                    timing: TimingBackend::LinuxKernelTimestamp,
                }
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_step_runs_its_sweeps_and_learns_the_distance() {
        let session = Arc::new(Mutex::new(Session::new(SweepPlan {
            interval: Duration::from_millis(2500),
            max_ttl: 10,
            timeout: TRACE_TIMEOUT,
        })));
        let seen = Arc::new(Mutex::new(0));
        let counter = Arc::clone(&seen);
        let t0 = Instant::now();
        let sweeps = run_step(Arc::new(Fake), Arc::clone(&session), 4, move |_| {
            *counter.lock().unwrap() += 1;
        })
        .await;
        assert_eq!(*seen.lock().unwrap(), 4);
        assert_eq!(sweeps.len(), 4);
        // The first sweep probes to max_ttl; later ones stop at the destination.
        assert_eq!(sweeps[0].hops.len(), 10);
        assert!(sweeps[1..].iter().all(|s| s.hops.len() == 3));
        // Three intervals, then the last sweep's probes.
        assert!(t0.elapsed() >= Duration::from_millis(7500));
        assert!(t0.elapsed() < Duration::from_millis(10_000));
        let rounds = hop_rounds(SystemTime::UNIX_EPOCH, ip(100), &sweeps);
        assert_eq!(rounds.len(), 3, "nothing past the destination");
        assert!(rounds.iter().all(|(_, r)| r.samples.len() == 4));
    }
}
