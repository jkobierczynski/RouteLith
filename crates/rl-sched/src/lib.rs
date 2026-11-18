//! Round scheduler: phase spreading, wall-clock alignment and rate limiting
//! (architecture doc §5.2).
//!
//! Each series runs as one task:
//!
//! - **Phase spreading:** the round starts `hash(vantage, target, family)
//!   mod step` into each step, so a thousand targets don't all fire at :00.
//! - **Wall-clock alignment:** slots are `k × step + offset` in Unix time,
//!   so agents measuring the same target line up.
//! - **Drift handling:** sleeps are recomputed from the wall clock at least
//!   once a minute; a disagreement of over a second between wall and
//!   monotonic time is logged and flagged on the round.
//! - **Overrun protection:** a round that runs past its next slot makes the
//!   scheduler skip to the following slot and count `round_overrun`; rounds
//!   never pile up.
//! - **Rate limit:** the ICMP probe shares an `rl_probe::RateLimiter`.
#![forbid(unsafe_code)]

mod hist;

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rl_core::config::{Family, Schedule};
use rl_core::{ResolvedTarget, RoundPlan, RoundResult};
use rl_probe::Probe;
use tokio::sync::watch;
use tokio::time::Instant;

pub use hist::Histogram;

/// A wall/monotonic disagreement above this is a clock step.
const CLOCK_STEP_US: i64 = 1_000_000;
/// Longest single sleep before re-reading the wall clock.
const MAX_SLEEP: Duration = Duration::from_secs(60);
/// Longest a round waits for its host name (and never longer than a step).
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Flag on a round: the wall clock stepped since the previous one.
pub const FLAG_CLOCK_STEP: u8 = 0x01;

/// One series to measure.
#[derive(Debug, Clone)]
pub struct Job {
    /// Store series id.
    pub series: u64,
    pub vantage: String,
    pub target: String,
    pub host: String,
    /// `V4`, `V6` or `PreferV6` (a `Both` target becomes two jobs).
    pub family: Family,
    /// For `PreferV6`: whether IPv6 may be used (false when this host
    /// cannot send ICMPv6, so the job measures over IPv4).
    pub v6_usable: bool,
    pub schedule: Schedule,
}

impl Job {
    /// Offset of this job's rounds inside each step.
    pub fn offset(&self) -> Duration {
        phase_offset(
            &[&self.vantage, &self.target, self.family.as_str()],
            self.schedule.step,
        )
    }

    fn label(&self) -> String {
        format!("{}/{}", self.target, self.family.as_str())
    }
}

/// `hash(parts) mod step`, stable across runs and platforms (FNV-1a).
pub fn phase_offset(parts: &[&str], step: Duration) -> Duration {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for b in part.bytes().chain([0xff]) {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    let step_ms = u64::try_from(step.as_millis()).unwrap_or(u64::MAX).max(1);
    Duration::from_millis(h % step_ms)
}

/// The first slot `k × step + offset` at or after `now_us` (Unix µs).
pub fn next_slot(now_us: i64, step: Duration, offset: Duration) -> i64 {
    let step = i64::try_from(step.as_micros()).unwrap_or(i64::MAX).max(1);
    let offset = i64::try_from(offset.as_micros()).unwrap_or(0) % step;
    let k = (now_us - offset).div_euclid(step);
    let slot = k * step + offset;
    if slot < now_us { slot + step } else { slot }
}

fn wall_us() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_micros()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_micros()).unwrap_or(i64::MAX),
    }
}

fn system_time(us: i64) -> SystemTime {
    if us >= 0 {
        UNIX_EPOCH + Duration::from_micros(us.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_micros(us.unsigned_abs())
    }
}

/// Why a round produced no samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailCause {
    /// The host name did not resolve for the job's family.
    Resolve,
    /// The probe could not run (socket error, permissions).
    Probe,
}

/// What a job hands to the store.
#[derive(Debug, Clone)]
pub enum Outcome {
    Measured(RoundResult),
    Failed {
        start: SystemTime,
        sent: u16,
        cause: FailCause,
        error: String,
    },
}

/// A finished round of one series.
#[derive(Debug, Clone)]
pub struct Completed {
    pub series: u64,
    pub outcome: Outcome,
    /// `FLAG_*` bits.
    pub flags: u8,
}

/// Where completed rounds go. Returns `false` if the round was dropped
/// (for example because the store queue is full).
pub type Sink = Arc<dyn Fn(Completed) -> bool + Send + Sync>;

/// Scheduler counters, shared by all jobs.
#[derive(Debug, Default)]
pub struct Stats {
    pub rounds: AtomicU64,
    /// Slots skipped because the previous round was still running.
    pub overruns: AtomicU64,
    pub clock_steps: AtomicU64,
    pub failed: AtomicU64,
    /// Rounds the sink refused.
    pub dropped: AtomicU64,
    /// How late each round started relative to its slot, in µs.
    lateness: Mutex<(Histogram, Histogram)>,
}

/// A snapshot of [`Stats`].
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub rounds: u64,
    pub overruns: u64,
    pub clock_steps: u64,
    pub failed: u64,
    pub dropped: u64,
    /// Since the previous `snapshot(true)`, or since start.
    pub lateness: Histogram,
}

impl Stats {
    fn record_lateness(&self, us: u64) {
        let mut h = self.lateness.lock().unwrap_or_else(PoisonError::into_inner);
        h.0.record(us);
        h.1.record(us);
    }

    /// Counters since start, and lateness either since start
    /// (`period = false`) or since the last periodic snapshot.
    pub fn snapshot(&self, period: bool) -> Snapshot {
        let lateness = {
            let mut h = self.lateness.lock().unwrap_or_else(PoisonError::into_inner);
            if period {
                std::mem::take(&mut h.0)
            } else {
                h.1.clone()
            }
        };
        Snapshot {
            rounds: self.rounds.load(Ordering::Relaxed),
            overruns: self.overruns.load(Ordering::Relaxed),
            clock_steps: self.clock_steps.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            lateness,
        }
    }
}

/// Resolve `host` for a job's family.
pub async fn resolve(host: &str, family: Family) -> Result<IpAddr, String> {
    let candidates: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(addr) => vec![addr],
        Err(_) => tokio::net::lookup_host((host, 0))
            .await
            .map_err(|e| e.to_string())?
            .map(|a| a.ip())
            .collect(),
    };
    let v4 = candidates.iter().copied().find(IpAddr::is_ipv4);
    let v6 = candidates.iter().copied().find(IpAddr::is_ipv6);
    let pick = match family {
        Family::V4 => v4,
        Family::V6 => v6,
        Family::PreferV6 | Family::Both => v6.or(v4),
    };
    pick.ok_or_else(|| format!("no {} address", family.as_str()))
}

/// Run one job until `shutdown` turns true.
pub async fn run_job(
    job: Job,
    probe: Arc<dyn Probe>,
    sink: Sink,
    stats: Arc<Stats>,
    mut shutdown: watch::Receiver<bool>,
) {
    let step = job.schedule.step;
    let step_us = i64::try_from(step.as_micros()).unwrap_or(i64::MAX);
    let offset = job.offset();
    let mut slot = next_slot(wall_us(), step, offset);
    let mut anchor: Option<(i64, Instant)> = None;
    let mut last_error: Option<String> = None;
    // Flags for the next round the sink accepts: a clock step seen on a
    // skipped slot or a refused round still marks the next stored round.
    let mut flags = 0;
    // A host lookup that outlived its round's timeout. The next round waits
    // for it instead of starting another, so each job has at most one
    // lookup in flight however slow the resolver is.
    let mut lookup: Option<Lookup> = None;
    loop {
        // Sleep until the slot, re-reading the wall clock at least once a
        // minute. A backward wall-clock step keeps the job waiting for the
        // slot it already chose: the store keeps each series' rounds in
        // strictly increasing time order, so a round stamped before the last
        // stored one would be dropped as late anyway. Rounds resume once the
        // wall clock reaches that slot again, and the step is flagged then.
        loop {
            if *shutdown.borrow() {
                return;
            }
            let left = slot - wall_us();
            if left <= 0 {
                break;
            }
            let nap = Duration::from_micros(left.unsigned_abs()).min(MAX_SLEEP);
            tokio::select! {
                () = tokio::time::sleep(nap) => {}
                // Resolves at once if shutdown is already true, and when the sender is gone.
                _ = shutdown.wait_for(|&stop| stop) => return,
            }
        }
        let (woke_wall, woke_mono) = (wall_us(), Instant::now());
        if let Some((wall, mono)) = anchor {
            let mono_us =
                i64::try_from(woke_mono.duration_since(mono).as_micros()).unwrap_or(i64::MAX);
            let drift = (woke_wall - wall) - mono_us;
            if drift.abs() > CLOCK_STEP_US {
                flags |= FLAG_CLOCK_STEP;
                stats.clock_steps.fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "routelith server: {}: wall clock moved {:+.3} s against the monotonic clock; flagging the round",
                    job.label(),
                    drift as f64 / 1e6
                );
            }
        }
        anchor = Some((woke_wall, woke_mono));
        let late = woke_wall - slot;
        // A wake far past the slot (sleep/resume, clock step): realign
        // instead of firing a stale round.
        if late > step_us {
            let new = next_slot(woke_wall, step, offset);
            // Every slot from the missed one up to (not including) the new one.
            let skipped = (new - slot) / step_us;
            stats
                .overruns
                .fetch_add(skipped.unsigned_abs(), Ordering::Relaxed);
            slot = new;
            continue;
        }
        stats.record_lateness(late.unsigned_abs());

        let start = system_time(slot);
        let outcome = tokio::select! {
            o = measure(&job, probe.as_ref(), start, &mut lookup) => o,
            _ = shutdown.wait_for(|&stop| stop) => return,
        };
        if let Outcome::Failed { error, .. } = &outcome {
            stats.failed.fetch_add(1, Ordering::Relaxed);
            // Log a failure once, not every round.
            if last_error.as_deref() != Some(error) {
                eprintln!("routelith server: {}: {error}", job.label());
                last_error = Some(error.clone());
            }
        } else if last_error.take().is_some() {
            eprintln!("routelith server: {}: measuring again", job.label());
        }
        stats.rounds.fetch_add(1, Ordering::Relaxed);
        let accepted = sink(Completed {
            series: job.series,
            outcome,
            flags,
        });
        if accepted {
            flags = 0;
        } else {
            stats.dropped.fetch_add(1, Ordering::Relaxed);
        }

        let next = slot + step_us;
        let now = wall_us();
        if now > next {
            // The slot the scheduler runs next is not skipped; the ones before it are.
            let new = next_slot(now, step, offset);
            let skipped = (new - next) / step_us;
            stats
                .overruns
                .fetch_add(skipped.unsigned_abs(), Ordering::Relaxed);
            slot = new;
        } else {
            slot = next;
        }
    }
}

type Lookup = tokio::task::JoinHandle<Result<IpAddr, String>>;

async fn measure(
    job: &Job,
    probe: &dyn Probe,
    start: SystemTime,
    lookup: &mut Option<Lookup>,
) -> Outcome {
    let s = job.schedule;
    let failed = |cause, error: String| Outcome::Failed {
        start,
        sent: s.pings,
        cause,
        error,
    };
    // A stalled resolver must not hold the job past its slot.
    let limit = RESOLVE_TIMEOUT.min(s.step);
    let family = if job.family == Family::PreferV6 && !job.v6_usable {
        Family::V4
    } else {
        job.family
    };
    let resolved = if let Ok(addr) = job.host.parse::<IpAddr>() {
        resolve(&addr.to_string(), family).await
    } else {
        // Reuse a lookup still running from an earlier round, else start one.
        let mut handle = lookup.take().unwrap_or_else(|| {
            let host = job.host.clone();
            tokio::spawn(async move { resolve(&host, family).await })
        });
        match tokio::time::timeout(limit, &mut handle).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => Err(format!("lookup task failed: {e}")),
            Err(_) => {
                *lookup = Some(handle);
                Err(format!(
                    "lookup did not finish within {}",
                    rl_core::duration::format(limit)
                ))
            }
        }
    };
    let addr = match resolved {
        Ok(a) => a,
        Err(e) => {
            return failed(
                FailCause::Resolve,
                format!("cannot resolve {}: {e}", job.host),
            );
        }
    };
    let target = ResolvedTarget {
        name: job.host.clone(),
        addr,
    };
    let plan = RoundPlan {
        count: s.pings,
        spread: s.spread,
        timeout: s.timeout,
        round_start: start,
    };
    match probe.run_round(&target, plan).await {
        Ok(r) => Outcome::Measured(r),
        Err(e) => failed(FailCause::Probe, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_are_stable_and_spread() {
        let step = Duration::from_secs(300);
        let a = phase_offset(&["local", "gw", "v4"], step);
        assert_eq!(a, phase_offset(&["local", "gw", "v4"], step));
        assert!(a < step);
        assert_ne!(a, phase_offset(&["local", "gw", "v6"], step));
        // Part boundaries matter: ("ab", "c") differs from ("a", "bc").
        assert_ne!(
            phase_offset(&["ab", "c"], step),
            phase_offset(&["a", "bc"], step)
        );
        // 1,000 targets land in most 1-second slots of a 300 s step.
        let mut used = std::collections::HashSet::new();
        for i in 0..1000 {
            used.insert(phase_offset(&["local", &format!("t{i}"), "v4"], step).as_secs());
        }
        assert!(used.len() > 250, "{}", used.len());
    }

    #[test]
    fn slots_are_wall_clock_aligned() {
        let step = Duration::from_secs(300);
        let off = Duration::from_secs(7);
        assert_eq!(next_slot(0, step, off), 7_000_000);
        assert_eq!(next_slot(7_000_000, step, off), 7_000_000);
        assert_eq!(next_slot(7_000_001, step, off), 307_000_000);
        assert_eq!(next_slot(-1, step, Duration::ZERO), 0);
        // Every slot is offset + k × step.
        let s = next_slot(1_763_456_789_123_456, step, off);
        assert_eq!((s - 7_000_000) % 300_000_000, 0);
        assert!((1_763_456_789_123_456..1_763_456_789_123_456 + 300_000_000).contains(&s));
    }

    #[tokio::test]
    async fn literals_resolve_by_family() {
        assert_eq!(
            resolve("127.0.0.1", Family::V4).await,
            Ok("127.0.0.1".parse().unwrap())
        );
        assert!(resolve("127.0.0.1", Family::V6).await.is_err());
        assert_eq!(
            resolve("::1", Family::PreferV6).await,
            Ok("::1".parse().unwrap())
        );
    }
}
