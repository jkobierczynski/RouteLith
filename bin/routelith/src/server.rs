//! `routelith server`: the scheduler and the store in the foreground
//! (M0: no UI or agent API yet).
//!
//! Probes run as tokio tasks, one per series. Finished rounds go through a
//! bounded queue to one store thread, which owns the [`Writer`], fsyncs the
//! WAL once a second and runs maintenance (checkpoints, day sealing).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Args;
use rl_core::config::{self, Config, Family};
use rl_probe::{IcmpConfig, IcmpProbe, Probe, RateLimiter};
use rl_sched::{Completed, FailCause, Job, Outcome, Sink, Snapshot, Stats};
use rl_store::{Appended, ErrorCounts, SeriesKey, StoredRound, Writer, WriterOptions};
use tokio::sync::watch;

/// Rounds waiting for the store thread before new ones are dropped.
const QUEUE: usize = 16_384;
/// WAL fsync and maintenance interval (§6.2).
const SYNC_EVERY: Duration = Duration::from_secs(1);

#[derive(Debug, Args)]
pub(crate) struct ServerArgs {
    /// Path to the TOML configuration file.
    #[arg(short, long)]
    config: PathBuf,
    /// Seconds between stats lines on stderr (0: only at exit; at most a day).
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(0..=86_400))]
    stats_interval: u64,
}

/// Exit codes: 0 after a clean shutdown, 1 invalid configuration,
/// 2 cannot start (unreadable file, store, privileges), or the store failed
/// or rejected rounds while running.
pub(crate) async fn run(args: ServerArgs) -> ExitCode {
    let cfg = match load(&args.config) {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let plans = series_plans(&cfg);
    if plans.is_empty() {
        eprintln!("routelith server: no targets to measure");
        return ExitCode::from(1);
    }
    // A v4 or v6 series needs its family; prefer-v6 can use either.
    let prefer = plans.iter().any(|p| p.family == Family::PreferV6);
    let mut usable = [true; 2];
    for v6 in [false, true] {
        let own = if v6 { Family::V6 } else { Family::V4 };
        let required = plans.iter().any(|p| p.family == own);
        if !required && !prefer {
            continue;
        }
        if let Err(e) = rl_probe::check_permission(v6) {
            usable[usize::from(v6)] = false;
            let msg = format!("cannot send ICMPv{}: {e}", if v6 { 6 } else { 4 });
            if required {
                eprintln!("routelith server: {msg}");
                return ExitCode::from(2);
            }
            eprintln!(
                "routelith server: warning: {msg}; prefer-v6 targets {}",
                if v6 {
                    "will use IPv4"
                } else {
                    "need an IPv6 address"
                }
            );
        }
    }
    if prefer && usable == [false, false] {
        eprintln!(
            "routelith server: prefer-v6 targets cannot be measured: neither ICMPv4 nor ICMPv6 is permitted"
        );
        return ExitCode::from(2);
    }

    let (mut writer, recovery) =
        match Writer::open(&cfg.server.data_dir, WriterOptions::default(), now_ms()) {
            Ok(w) => w,
            Err(e) => {
                eprintln!(
                    "routelith server: cannot open {}: {e}",
                    cfg.server.data_dir.display()
                );
                return ExitCode::from(2);
            }
        };
    let repaired = recovery.replayed > 0
        || recovery.torn_wal > 0
        || recovery.truncated_segments > 0
        || !recovery.problems.is_empty();
    if repaired {
        eprintln!(
            "routelith server: recovery: {} WAL file(s), {} round(s) replayed, {} already stored, {} torn WAL, {} segment(s) trimmed",
            recovery.wal_files,
            recovery.replayed,
            recovery.skipped,
            recovery.torn_wal,
            recovery.truncated_segments
        );
        for p in &recovery.problems {
            eprintln!("routelith server: recovery: {p}");
        }
    }
    let keys: Vec<SeriesKey> = plans
        .iter()
        .map(|p| SeriesKey::new(&cfg.server.vantage, &p.target, p.family.as_str()))
        .collect();
    let ids = match writer.register(&keys) {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("routelith server: cannot register series: {e}");
            return ExitCode::from(2);
        }
    };

    // Install the signal handlers before any work starts, so a SIGTERM
    // right after start-up still shuts down cleanly.
    let signal = match shutdown_signal() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("routelith server: cannot listen for shutdown signals: {e}");
            return ExitCode::from(2);
        }
    };

    let (tx, rx) = mpsc::sync_channel::<Completed>(QUEUE);
    // Tells the main loop when the store thread ends early (after an error).
    let (store_done_tx, mut store_done) = tokio::sync::oneshot::channel::<()>();
    let store = std::thread::spawn(move || {
        let r = store_loop(writer, &rx);
        let _ = store_done_tx.send(());
        r
    });
    let sink: Sink = Arc::new(move |c| tx.try_send(c).is_ok());

    let limiter = Arc::new(RateLimiter::new(cfg.server.max_pps));
    let mut probes: HashMap<u16, Arc<dyn Probe>> = HashMap::new();
    let stats = Arc::new(Stats::default());
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut jobs = tokio::task::JoinSet::new();
    for (plan, series) in plans.into_iter().zip(ids) {
        let probe = probes
            .entry(plan.payload_size)
            .or_insert_with(|| {
                Arc::new(
                    IcmpProbe::new(IcmpConfig {
                        payload_size: plan.payload_size,
                    })
                    .with_rate_limiter(limiter.clone()),
                )
            })
            .clone();
        let job = Job {
            v6_usable: usable[1],
            series,
            vantage: cfg.server.vantage.clone(),
            target: plan.target,
            host: plan.host,
            family: plan.family,
            schedule: plan.schedule,
        };
        jobs.spawn(rl_sched::run_job(
            job,
            probe,
            sink.clone(),
            stats.clone(),
            stop_rx.clone(),
        ));
    }
    drop(sink);
    eprintln!(
        "routelith server: measuring {} series of {} targets from vantage {:?}, data in {}",
        jobs.len(),
        cfg.targets.len(),
        cfg.server.vantage,
        cfg.server.data_dir.display()
    );

    let interval = Duration::from_secs(args.stats_interval);
    let mut ticker = tokio::time::interval(if interval.is_zero() {
        Duration::from_secs(3600 * 24 * 365)
    } else {
        interval
    });
    ticker.tick().await;
    let started = Instant::now();
    tokio::pin!(signal);
    loop {
        tokio::select! {
            () = &mut signal => break,
            _ = &mut store_done => {
                eprintln!("routelith server: the store stopped after an error; shutting down");
                break;
            }
            _ = ticker.tick() => {
                if !interval.is_zero() {
                    eprintln!("routelith server: {}", stats_line(&stats.snapshot(true), "last"));
                }
            }
        }
    }

    eprintln!("routelith server: stopping");
    let _ = stop_tx.send(true);
    while jobs.join_next().await.is_some() {}
    let ok = match store.join() {
        Ok(Ok(0)) => true,
        Ok(Ok(n)) => {
            eprintln!("routelith server: store: {n} invalid round(s) were rejected and not stored");
            false
        }
        Ok(Err(e)) => {
            eprintln!("routelith server: store: {e}");
            false
        }
        Err(_) => {
            eprintln!("routelith server: store thread panicked");
            false
        }
    };
    eprintln!(
        "stats: uptime_s={} {}",
        started.elapsed().as_secs(),
        stats_line(&stats.snapshot(false), "all")
    );
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn load(path: &Path) -> Result<Config, ExitCode> {
    let bytes = std::fs::read(path).map_err(|e| {
        eprintln!("routelith server: {}: {e}", path.display());
        ExitCode::from(2)
    })?;
    // Readable but not UTF-8: an invalid configuration, like `ctl verify` says.
    let src = String::from_utf8(bytes).map_err(|e| {
        eprintln!("routelith server: {}: not valid UTF-8: {e}", path.display());
        ExitCode::from(1)
    })?;
    let parsed = config::parse(&src);
    for d in &parsed.diagnostics {
        eprintln!("{}:{d}", path.display());
    }
    parsed.config.ok_or_else(|| {
        eprintln!(
            "routelith server: {} is invalid; check it with `routelith ctl verify`",
            path.display()
        );
        ExitCode::from(1)
    })
}

/// One series to measure, before it has an id.
#[derive(Debug, Clone, PartialEq)]
struct SeriesPlan {
    target: String,
    host: String,
    family: Family,
    schedule: rl_core::config::Schedule,
    payload_size: u16,
}

/// Targets as series: a `both` target measures v4 and v6 separately.
fn series_plans(cfg: &Config) -> Vec<SeriesPlan> {
    let mut out = Vec::new();
    for t in &cfg.targets {
        let families: &[Family] = match t.family {
            Family::Both => &[Family::V4, Family::V6],
            Family::V4 => &[Family::V4],
            Family::V6 => &[Family::V6],
            Family::PreferV6 => &[Family::PreferV6],
        };
        for &family in families {
            out.push(SeriesPlan {
                target: t.id.clone(),
                host: t.host.clone(),
                family,
                schedule: t.schedule,
                payload_size: t.payload_size,
            });
        }
    }
    out
}

fn now_ms() -> i64 {
    to_ms(SystemTime::now())
}

fn to_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// The stored form of a finished round. A round that could not run counts
/// every sample as an error of its cause.
fn stored(c: &Completed) -> Result<StoredRound, rl_store::StoreError> {
    let flags = if c.flags & rl_sched::FLAG_CLOCK_STEP != 0 {
        rl_store::FLAG_CLOCK_STEP
    } else {
        0
    };
    match &c.outcome {
        Outcome::Measured(r) => StoredRound::from_result(r, flags),
        Outcome::Failed {
            start, sent, cause, ..
        } => {
            let mut errors = ErrorCounts::default();
            match cause {
                FailCause::Resolve => errors.other = *sent,
                FailCause::Probe => errors.send_failed = *sent,
            }
            Ok(StoredRound {
                ts_ms: to_ms(*start),
                sent: *sent,
                rtts_us: Vec::new(),
                errors,
                resolved: None,
                timing: None,
                flags,
            })
        }
    }
}

/// Own the writer: append rounds as they come, fsync and maintain once a
/// second, close when every sender is gone.
///
/// The writer is fail-stop, so any error other than a single invalid round
/// ends the loop; the server then shuts down and a restart runs recovery.
/// Returns how many rounds were rejected as invalid (and so not stored).
fn store_loop(mut w: Writer, rx: &mpsc::Receiver<Completed>) -> Result<u64, rl_store::StoreError> {
    let (mut late, mut rejected) = (0u64, 0u64);
    let result = store_rounds(&mut w, rx, &mut late, &mut rejected);
    if late > 0 {
        eprintln!(
            "routelith server: store: {late} round(s) were not newer than the last one and were dropped"
        );
    }
    result?;
    w.close()?;
    Ok(rejected)
}

fn store_rounds(
    w: &mut Writer,
    rx: &mpsc::Receiver<Completed>,
    late: &mut u64,
    rejected: &mut u64,
) -> Result<(), rl_store::StoreError> {
    let mut next_sync = Instant::now() + SYNC_EVERY;
    let mut last_invalid: Option<String> = None;
    loop {
        let wait = next_sync.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(c) => match stored(&c).and_then(|r| w.append(c.series, r)) {
                Ok(Appended::Stored) => {}
                Ok(Appended::Late) => *late += 1,
                Err(rl_store::StoreError::InvalidRound(msg)) => {
                    *rejected += 1;
                    if last_invalid.as_deref() != Some(msg) {
                        eprintln!(
                            "routelith server: store: series {}: invalid round: {msg}",
                            c.series
                        );
                        last_invalid = Some(msg.to_string());
                    }
                }
                Err(e) => return Err(e),
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        if Instant::now() >= next_sync {
            next_sync += SYNC_EVERY;
            w.sync()?;
            w.maintain(now_ms())?;
        }
    }
}

fn stats_line(s: &Snapshot, window: &str) -> String {
    let ms =
        |us: Option<u64>| us.map_or_else(|| "-".to_string(), |v| format!("{:.3}", v as f64 / 1e3));
    format!(
        "rounds={} overruns={} lateness_{window}_p50_ms={} lateness_{window}_p99_ms={} lateness_{window}_max_ms={} clock_steps={} dropped={} failed={}",
        s.rounds,
        s.overruns,
        ms(s.lateness.percentile(50.0)),
        ms(s.lateness.percentile(99.0)),
        ms((s.lateness.count() > 0).then(|| s.lateness.max())),
        s.clock_steps,
        s.dropped,
        s.failed,
    )
}

/// Ctrl-C everywhere, SIGTERM on Unix.
/// Install the Ctrl-C and SIGTERM handlers now; the returned future
/// completes on the first signal.
fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        Ok(async move {
            tokio::select! {
                _ = int.recv() => {}
                _ = term.recv() => {}
            }
        })
    }
    #[cfg(windows)]
    {
        let mut c = tokio::signal::windows::ctrl_c()?;
        let mut brk = tokio::signal::windows::ctrl_break()?;
        Ok(async move {
            tokio::select! {
                _ = c.recv() => {}
                _ = brk.recv() => {}
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_targets_become_two_series() {
        let src = "[server]\ndata_dir = \"/tmp/x\"\n[[group]]\nname = \"g\"\n[[group.target]]\nname = \"a\"\nhost = \"127.0.0.1\"\n[[group.target]]\nname = \"b\"\nhost = \"localhost\"\nfamily = \"both\"\n";
        let parsed = config::parse(src);
        let cfg = parsed.config.expect("valid config");
        assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
        let fams: Vec<_> = series_plans(&cfg)
            .iter()
            .map(|p| (p.target.clone(), p.family.as_str()))
            .collect();
        assert_eq!(
            fams,
            [
                ("a".to_string(), "v4"),
                ("b".to_string(), "v4"),
                ("b".to_string(), "v6")
            ]
        );
    }

    #[test]
    fn failed_rounds_count_every_sample_as_an_error() {
        let c = Completed {
            series: 1,
            outcome: Outcome::Failed {
                start: UNIX_EPOCH + Duration::from_secs(60),
                sent: 20,
                cause: FailCause::Resolve,
                error: "nope".into(),
            },
            flags: rl_sched::FLAG_CLOCK_STEP,
        };
        let r = stored(&c).unwrap();
        assert_eq!((r.ts_ms, r.sent, r.loss()), (60_000, 20, 20));
        assert_eq!(r.errors.other, 20);
        assert_eq!(r.flags, rl_store::FLAG_CLOCK_STEP);
    }

    #[test]
    fn an_invalid_round_does_not_stop_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let (mut w, _) = Writer::open(dir.path(), WriterOptions::default(), 0).unwrap();
        let id = w.register(&[SeriesKey::new("local", "t", "v4")]).unwrap()[0];
        let failed = |secs: u64| Completed {
            series: id,
            outcome: Outcome::Failed {
                start: UNIX_EPOCH + Duration::from_secs(secs),
                sent: 20,
                cause: FailCause::Probe,
                error: "nope".into(),
            },
            flags: 0,
        };
        let (tx, rx) = mpsc::sync_channel(4);
        // Year 11,000: outside what the store accepts.
        tx.send(failed(284_000_000_000)).unwrap();
        tx.send(failed(1_800_000_000)).unwrap();
        drop(tx);
        assert_eq!(store_loop(w, &rx).unwrap(), 1);
        let rounds = rl_store::Reader::open(dir.path())
            .unwrap()
            .read(id, 0, i64::MAX)
            .unwrap();
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].ts_ms, 1_800_000_000_000);
    }
}
