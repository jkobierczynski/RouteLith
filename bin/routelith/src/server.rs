//! `routelith server`: the scheduler, the store and the HTTP side (web UI,
//! REST API, `/metrics`) in the foreground. No agent API yet (M3).
//!
//! Probes run as tokio tasks, one per series. Finished rounds go through a
//! bounded queue to one store thread, which owns the [`Writer`], fsyncs the
//! WAL once a second and runs maintenance (checkpoints, day sealing,
//! rollups). The HTTP side reads the store through its own [`Reader`].
//! A health thread samples this machine once a minute (see `health`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Args;
use rl_core::config::{self, Config, Family, ProbeConfig};
use rl_probe::{
    DnsProbe, HttpProbe, IcmpConfig, IcmpProbe, Probe, ProbeError, RateLimiter, TcpConfig, TcpProbe,
};
use rl_sched::{Completed, FailCause, Job, Outcome, Sink, Snapshot, Stats};
use rl_store::{
    Appended, ErrorCounts, Reader, SeriesKey, StoredRound, Writer, WriterOptions, WriterStats,
};
use rl_web::{AppState, HttpPhases, Latest, LatestHost, LatestRound, MetricsWriter, SeriesInfo};
use tokio::sync::watch;

/// Rounds waiting for the store thread before new ones are dropped.
const QUEUE: usize = 16_384;
/// WAL fsync and maintenance interval (§6.2).
const SYNC_EVERY: Duration = Duration::from_secs(1);

#[derive(Debug, Args)]
pub(crate) struct ServerArgs {
    /// Path to the TOML configuration file.
    #[arg(short, long)]
    pub(crate) config: PathBuf,
    /// Seconds between stats lines on stderr (0: only at exit; at most a day).
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(0..=86_400))]
    pub(crate) stats_interval: u64,
}

/// Exit codes: 0 after a clean shutdown, 1 invalid configuration,
/// 2 cannot start (unreadable file, store, privileges), or the store failed
/// or rejected rounds while running.
pub(crate) async fn run(args: ServerArgs) -> ExitCode {
    // Install the signal handlers before any work starts, so a SIGTERM
    // right after start-up still shuts down cleanly.
    match shutdown_signal() {
        Ok(signal) => serve(args, signal).await,
        Err(e) => {
            eprintln!("routelith server: cannot listen for shutdown signals: {e}");
            ExitCode::from(2)
        }
    }
}

/// Run until `stop` completes (a signal, or the Windows service manager).
pub(crate) async fn serve(
    args: ServerArgs,
    signal: impl std::future::Future<Output = ()>,
) -> ExitCode {
    let cfg = match load(&args.config) {
        Ok(cfg) => cfg,
        Err(code) => return code,
    };
    let plans = series_plans(&cfg);
    if plans.is_empty() {
        eprintln!("routelith server: no targets to measure");
        return ExitCode::from(1);
    }
    // An ICMP series needs an ICMP socket of its family; prefer-v6 can use
    // either. Other probes use ordinary sockets.
    let icmp = |p: &&SeriesPlan| matches!(p.probe, ProbeConfig::Icmp { .. });
    let prefer = plans
        .iter()
        .filter(icmp)
        .any(|p| p.family == Family::PreferV6);
    let mut usable = [true; 2];
    for v6 in [false, true] {
        let own = if v6 { Family::V6 } else { Family::V4 };
        let required = plans.iter().filter(icmp).any(|p| p.family == own);
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
    let steps: Vec<(u64, u64)> = ids
        .iter()
        .zip(&plans)
        .map(|(&id, p)| {
            let ms = u64::try_from(p.schedule.step.as_millis()).unwrap_or(u64::MAX);
            (id, ms)
        })
        .collect();
    if let Err(e) = writer.set_steps(&steps) {
        eprintln!("routelith server: cannot record series steps: {e}");
        return ExitCode::from(2);
    }

    // The HTTP side: bind now, so a port in use stops start-up.
    let latest = Arc::new(Latest::default());
    let host = Arc::new(LatestHost::default());
    let store_stats = Arc::new(Mutex::new(StoreCounters::default()));
    let stats = Arc::new(Stats::default());
    let web = match cfg.server.listen_ui {
        None => None,
        Some(addr) => {
            let reader = match Reader::open(&cfg.server.data_dir) {
                Ok(r) => Arc::new(r),
                Err(e) => {
                    eprintln!("routelith server: cannot read the store: {e}");
                    return ExitCode::from(2);
                }
            };
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("routelith server: cannot listen on {addr} (listen_ui): {e}");
                    return ExitCode::from(2);
                }
            };
            let state = AppState {
                reader,
                data_dir: cfg.server.data_dir.clone(),
                host: host.clone(),
                series: series_infos(&plans, &ids, &cfg.server.vantage),
                latest: latest.clone(),
                vantage: cfg.server.vantage.clone(),
                started: Instant::now(),
                extra_metrics: Some(extra_metrics(stats.clone(), store_stats.clone())),
            };
            Some((addr, listener, rl_web::router(Arc::new(state))))
        }
    };

    let (tx, rx) = mpsc::sync_channel::<Completed>(QUEUE);
    // Tells the main loop when the store thread ends early (after an error).
    let (store_done_tx, mut store_done) = tokio::sync::oneshot::channel::<()>();
    let store_latest = latest.clone();
    let shared_counters = store_stats.clone();
    let store = std::thread::spawn(move || {
        let r = store_loop(writer, &rx, &store_latest, &shared_counters);
        let _ = store_done_tx.send(());
        r
    });
    let sink: Sink = Arc::new(move |c| tx.try_send(c).is_ok());
    let (health_stop, health_rx) = mpsc::channel::<()>();
    let health = match crate::health::spawn(
        cfg.server.data_dir.clone(),
        cfg.server.vantage.clone(),
        host,
        health_rx,
        now_ms,
    ) {
        Ok(h) => Some(h),
        Err(e) => {
            eprintln!("routelith server: warning: no health snapshots: {e}");
            None
        }
    };

    let limiter = Arc::new(RateLimiter::new(cfg.server.max_pps));
    let mut probes: HashMap<ProbeConfig, Arc<dyn Probe>> = HashMap::new();
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut jobs = tokio::task::JoinSet::new();
    for (plan, series) in plans.into_iter().zip(ids) {
        let probe = match probes.get(&plan.probe) {
            Some(p) => p.clone(),
            None => match make_probe(&plan.probe, &limiter) {
                Ok(p) => probes.entry(plan.probe.clone()).or_insert(p).clone(),
                Err(e) => {
                    eprintln!("routelith server: target {}: {e}", plan.target);
                    return ExitCode::from(1);
                }
            },
        };
        let job = Job {
            // Only ICMP depends on this process's socket permissions.
            v6_usable: usable[1] || !matches!(plan.probe, ProbeConfig::Icmp { .. }),
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
    let web = web.map(|(addr, listener, router)| {
        eprintln!("routelith server: web UI and API on http://{addr}/");
        let mut stop = stop_rx.clone();
        tokio::spawn(rl_web::serve(listener, router, async move {
            let _ = stop.wait_for(|s| *s).await;
        }))
    });
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
    // The store ends on its own only after an error, or when every job has
    // ended; a job ends on its own only by panicking. Either way monitoring
    // stopped without being asked to, which is a failure.
    let mut stopped_early = false;
    let mut panicked = 0usize;
    loop {
        tokio::select! {
            () = &mut signal => break,
            // A job ends only when asked to stop: one ending now (a panic)
            // leaves its series unmeasured, so shut down with a failure.
            Some(r) = jobs.join_next(), if !jobs.is_empty() => {
                if r.is_err() {
                    panicked += 1;
                }
                eprintln!(
                    "routelith server: a scheduler task ended before shutdown was requested; \
                     shutting down"
                );
                stopped_early = true;
                break;
            }
            _ = &mut store_done => {
                eprintln!(
                    "routelith server: the store stopped before shutdown was requested; \
                     shutting down"
                );
                stopped_early = true;
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
    while let Some(r) = jobs.join_next().await {
        if r.is_err() {
            panicked += 1;
        }
    }
    if panicked > 0 {
        eprintln!("routelith server: {panicked} scheduler task(s) failed");
    }
    drop(health_stop);
    if let Some(h) = health {
        if h.join().is_err() {
            eprintln!("routelith server: health thread panicked");
        }
    }
    let mut web_ok = true;
    if let Some(task) = web {
        // In-flight requests finish; open keep-alive connections are not
        // waited for past a few seconds.
        match tokio::time::timeout(Duration::from_secs(5), task).await {
            Ok(Ok(Ok(()))) | Err(_) => {}
            Ok(Ok(Err(e))) => {
                eprintln!("routelith server: web: {e}");
                web_ok = false;
            }
            Ok(Err(_)) => {
                eprintln!("routelith server: web task panicked");
                web_ok = false;
            }
        }
    }
    let store_ok = match store.join() {
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
    if store_ok && web_ok && !stopped_early && panicked == 0 {
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
    group: String,
    schedule: rl_core::config::Schedule,
    probe: ProbeConfig,
}

/// One probe instance per distinct probe configuration, all sharing the
/// packets-per-second ceiling.
fn make_probe(cfg: &ProbeConfig, limiter: &Arc<RateLimiter>) -> Result<Arc<dyn Probe>, ProbeError> {
    Ok(match cfg {
        &ProbeConfig::Tcp { port, mode } => {
            Arc::new(TcpProbe::new(TcpConfig { port, mode }).with_rate_limiter(limiter.clone()))
        }
        &ProbeConfig::Icmp { payload_size } => {
            Arc::new(IcmpProbe::new(IcmpConfig { payload_size }).with_rate_limiter(limiter.clone()))
        }
        ProbeConfig::Dns(d) => {
            Arc::new(DnsProbe::new(d.clone())?.with_rate_limiter(limiter.clone()))
        }
        ProbeConfig::Http(h) => {
            Arc::new(HttpProbe::new(h.clone())?.with_rate_limiter(limiter.clone()))
        }
    })
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
                group: t.group.clone(),
                family,
                schedule: t.schedule,
                probe: t.probe.clone(),
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
fn store_loop(
    mut w: Writer,
    rx: &mpsc::Receiver<Completed>,
    latest: &Latest,
    counters: &Mutex<StoreCounters>,
) -> Result<u64, rl_store::StoreError> {
    let (mut late, mut rejected) = (0u64, 0u64);
    let result = store_rounds(&mut w, rx, latest, counters, &mut late, &mut rejected);
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
    latest: &Latest,
    counters: &Mutex<StoreCounters>,
    late: &mut u64,
    rejected: &mut u64,
) -> Result<(), rl_store::StoreError> {
    let mut next_sync = Instant::now() + SYNC_EVERY;
    let mut last_invalid: Option<String> = None;
    loop {
        let wait = next_sync.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(c) => match stored(&c).and_then(|r| {
                let newest = latest_round(&c, &r);
                w.append(c.series, r).map(|a| (a, newest))
            }) {
                Ok((Appended::Stored, newest)) => latest.record(c.series, newest),
                Ok((Appended::Late, _)) => *late += 1,
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
            *counters.lock().unwrap_or_else(PoisonError::into_inner) = StoreCounters {
                writer: w.stats(),
                wal_bytes: w.wal_bytes(),
                rejected: *rejected,
            };
        }
    }
}

/// What `/metrics` shows of the store, refreshed once a second.
#[derive(Debug, Clone, Copy, Default)]
struct StoreCounters {
    writer: WriterStats,
    wal_bytes: u64,
    rejected: u64,
}

/// The API's view of the series.
fn series_infos(plans: &[SeriesPlan], ids: &[u64], vantage: &str) -> Vec<SeriesInfo> {
    plans
        .iter()
        .zip(ids)
        .map(|(p, &id)| {
            let (probe, url) = match &p.probe {
                ProbeConfig::Icmp { .. } => ("icmp", None),
                ProbeConfig::Tcp { .. } => ("tcp", None),
                ProbeConfig::Dns(_) => ("dns", None),
                ProbeConfig::Http(h) => ("http", Some(h.url.clone())),
            };
            SeriesInfo {
                id,
                key: SeriesKey::new(vantage, &p.target, p.family.as_str()),
                group: p.group.clone(),
                probe: probe.to_string(),
                host: p.host.clone(),
                url,
                step_ms: u64::try_from(p.schedule.step.as_millis()).unwrap_or(u64::MAX),
                pings: p.schedule.pings,
            }
        })
        .collect()
}

/// The `p`th percentile (0 to 100) of an ascending slice by nearest rank:
/// the smallest value with at least `p` % of the values at or below it.
fn nearest_rank(sorted: &[u32], p: usize) -> Option<u32> {
    let n = sorted.len();
    if n == 0 {
        return None;
    }
    let rank = (p * n).div_ceil(100).max(1);
    Some(sorted[rank.min(n) - 1])
}

/// The newest round as `/metrics` shows it.
fn latest_round(c: &Completed, r: &StoredRound) -> LatestRound {
    let q = |p: usize| nearest_rank(&r.rtts_us, p);
    let http = match &c.outcome {
        Outcome::Measured(m) => m.http.as_ref(),
        Outcome::Failed { .. } => None,
    };
    let http_phases_us = http.map(|h| {
        let done: Vec<&rl_core::round::PhaseTimings> = h.phases.iter().flatten().collect();
        let median = |f: &dyn Fn(&rl_core::round::PhaseTimings) -> Option<u32>| {
            let mut v: Vec<u32> = done.iter().filter_map(|p| f(p)).collect();
            v.sort_unstable();
            (!v.is_empty()).then(|| v[(v.len() - 1) / 2])
        };
        HttpPhases {
            connect: median(&|p| Some(p.connect_us)),
            tls: median(&|p| p.tls_us),
            ttfb: median(&|p| Some(p.ttfb_us)),
            total: median(&|p| Some(p.total_us)),
        }
    });
    LatestRound {
        ts_ms: r.ts_ms,
        sent: u32::from(r.sent),
        received: u32::try_from(r.rtts_us.len()).unwrap_or(u32::MAX),
        min_us: q(0),
        median_us: q(50),
        p90_us: q(90),
        max_us: q(100),
        errors: r.errors.total(),
        http_phases_us,
        cert_not_after_s: http
            .and_then(|h| h.cert_not_after)
            .map(|t| to_ms(t).div_euclid(1000)),
    }
}

/// Scheduler and store counters for `/metrics`.
fn extra_metrics(stats: Arc<Stats>, store: Arc<Mutex<StoreCounters>>) -> rl_web::ExtraMetrics {
    Arc::new(move |m: &mut MetricsWriter| {
        let s = stats.snapshot(false);
        let st = *store.lock().unwrap_or_else(PoisonError::into_inner);
        #[allow(clippy::cast_precision_loss)]
        let counters: [(&str, &str, u64); 11] = [
            (
                "routelith_rounds_total",
                "Rounds the scheduler finished.",
                s.rounds,
            ),
            (
                "routelith_round_overruns_total",
                "Rounds that started late because the previous one ran over.",
                s.overruns,
            ),
            (
                "routelith_clock_steps_total",
                "Wall-clock steps the scheduler noticed.",
                s.clock_steps,
            ),
            (
                "routelith_rounds_failed_total",
                "Rounds that could not run (name resolution or probe failure).",
                s.failed,
            ),
            (
                "routelith_rounds_dropped_total",
                "Rounds dropped because the store queue was full.",
                s.dropped,
            ),
            (
                "routelith_store_rounds_appended_total",
                "Rounds written to the store.",
                st.writer.appended,
            ),
            (
                "routelith_store_rounds_late_total",
                "Rounds dropped as not newer than the series' last one.",
                st.writer.late,
            ),
            (
                "routelith_store_rounds_rejected_total",
                "Rounds the store rejected as invalid.",
                st.rejected,
            ),
            (
                "routelith_store_days_sealed_total",
                "Day segments sealed.",
                st.writer.sealed,
            ),
            (
                "routelith_store_days_rolled_total",
                "Sealed days consolidated into the rollup tiers.",
                st.writer.rolled_days,
            ),
            (
                "routelith_store_files_expired_total",
                "Files deleted by retention.",
                st.writer.expired_files,
            ),
        ];
        for (name, help, v) in counters {
            m.family(name, "counter", help);
            #[allow(clippy::cast_precision_loss)]
            m.sample(name, &[], v as f64);
        }
        m.family(
            "routelith_store_wal_bytes",
            "gauge",
            "Size of the write-ahead log.",
        );
        #[allow(clippy::cast_precision_loss)]
        m.sample("routelith_store_wal_bytes", &[], st.wal_bytes as f64);
        m.family(
            "routelith_schedule_lateness_seconds",
            "gauge",
            "How late rounds started since the server started, by quantile.",
        );
        for (label, p) in [("0.5", 50.0), ("0.99", 99.0)] {
            if let Some(us) = s.lateness.percentile(p) {
                #[allow(clippy::cast_precision_loss)]
                m.sample(
                    "routelith_schedule_lateness_seconds",
                    &[("quantile", label)],
                    us as f64 / 1e6,
                );
            }
        }
    })
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
    fn the_newest_round_is_summarised_for_metrics() {
        use rl_core::round::{HttpRound, PhaseTimings};
        let phase = |c: u32, tls: u32| {
            Some(PhaseTimings {
                connect_us: c,
                tls_us: Some(tls),
                ttfb_us: c + tls + 100,
                total_us: c + tls + 200,
            })
        };
        let mut r = rl_core::round::RoundResult {
            start: UNIX_EPOCH + Duration::from_secs(600),
            samples: [300, 100, 200]
                .map(|rtt_us| rl_core::Sample::Ok { rtt_us })
                .into_iter()
                .chain([rl_core::Sample::Lost])
                .collect(),
            meta: rl_core::ProbeMeta {
                resolved: "192.0.2.1".parse().unwrap(),
                timing: rl_core::TimingSource::new(rl_core::TimingBackend::Monotonic),
                payload_size: 0,
            },
            http: Some(HttpRound {
                phases: vec![phase(10, 50), None, phase(30, 70), phase(20, 60)],
                cert_not_after: Some(UNIX_EPOCH + Duration::from_millis(1_900_000_000_500)),
            }),
        };
        let c = Completed {
            series: 1,
            outcome: Outcome::Measured(r.clone()),
            flags: 0,
        };
        let l = latest_round(&c, &stored(&c).unwrap());
        assert_eq!((l.ts_ms, l.sent, l.received, l.errors), (600_000, 4, 3, 0));
        assert_eq!(
            (l.min_us, l.median_us, l.p90_us, l.max_us),
            (Some(100), Some(200), Some(300), Some(300))
        );
        let p = l.http_phases_us.unwrap();
        assert_eq!(
            (p.connect, p.tls, p.ttfb, p.total),
            (Some(20), Some(60), Some(180), Some(280))
        );
        assert_eq!(l.cert_not_after_s, Some(1_900_000_000));

        r.http = None;
        r.samples = vec![rl_core::Sample::Lost];
        let c = Completed {
            series: 1,
            outcome: Outcome::Measured(r),
            flags: 0,
        };
        let l = latest_round(&c, &stored(&c).unwrap());
        assert_eq!((l.median_us, l.http_phases_us), (None, None));
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        let seven = [100, 200, 300, 400, 500, 600, 700];
        assert_eq!(nearest_rank(&seven, 90), Some(700));
        assert_eq!(nearest_rank(&seven, 50), Some(400));
        assert_eq!(nearest_rank(&seven, 0), Some(100));
        assert_eq!(nearest_rank(&seven, 100), Some(700));
        assert_eq!(nearest_rank(&[100, 200], 50), Some(100));
        assert_eq!(nearest_rank(&[100, 200], 90), Some(200));
        assert_eq!(nearest_rank(&[], 50), None);
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
        let latest = Latest::default();
        let counters = Mutex::new(StoreCounters::default());
        assert_eq!(store_loop(w, &rx, &latest, &counters).unwrap(), 1);
        let rounds = rl_store::Reader::open(dir.path())
            .unwrap()
            .read(id, 0, i64::MAX)
            .unwrap();
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].ts_ms, 1_800_000_000_000);
    }
}
