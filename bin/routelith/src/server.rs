//! `routelith server`: the scheduler, the store and the HTTP side (web UI,
//! REST API, `/metrics`) in the foreground, and with `listen_agents` the
//! agent link (M3): agents' rounds go to the same store thread.
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

use crate::alerting::Alerting;
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
    // Agents named in `vantages`, plus every enrolled agent when a group
    // says "*" (agents enrolled later get those after a restart).
    let agent_names = match agent_vantages(&cfg) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("routelith server: {e}");
            return ExitCode::from(2);
        }
    };
    let plans = series_plans(&cfg, &agent_names);
    if plans.is_empty() {
        eprintln!("routelith server: no targets to measure");
        return ExitCode::from(1);
    }
    let local_n = plans
        .iter()
        .take_while(|p| p.vantage == cfg.server.vantage)
        .count();
    let local = &plans[..local_n];
    let agent_series = plans.len() - local_n;
    // An ICMP series needs an ICMP socket of its family; prefer-v6 can use
    // either. Other probes use ordinary sockets.
    let icmp = |p: &&SeriesPlan| matches!(p.probe, ProbeConfig::Icmp { .. });
    let prefer = local
        .iter()
        .filter(icmp)
        .any(|p| p.family == Family::PreferV6);
    let mut usable = [true; 2];
    for v6 in [false, true] {
        let own = if v6 { Family::V6 } else { Family::V4 };
        let required = local.iter().filter(icmp).any(|p| p.family == own);
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
                let dir = &cfg.server.data_dir;
                if dir.is_absolute() {
                    eprintln!("routelith server: cannot open {}: {e}", dir.display());
                } else {
                    // Say where a relative path ended up: under a service
                    // the working directory is not the config's folder.
                    let full = std::path::absolute(dir).unwrap_or_else(|_| dir.clone());
                    eprintln!(
                        "routelith server: cannot open {} (relative to the working \
                         directory, so {}): {e}; set server.data_dir to an absolute path",
                        dir.display(),
                        full.display()
                    );
                }
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
        .map(|p| SeriesKey::new(&p.vantage, &p.target, p.family.as_str()))
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

    // What can still stop start-up comes before the alert engine, which
    // logs "server started" and hands it to the outputs: an exit after it
    // would cut their delivery short and leave no "server stopped".
    let limiter = Arc::new(RateLimiter::new(cfg.server.max_pps));
    let mut probes: HashMap<ProbeConfig, Arc<dyn Probe>> = HashMap::new();
    let mut plan_probes = Vec::with_capacity(local_n);
    for plan in &plans[..local_n] {
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
        plan_probes.push(probe);
    }
    // The HTTP side: bind now, so a port in use stops start-up.
    let ui = match cfg.server.listen_ui {
        None => None,
        Some(addr) => {
            let reader = match Reader::open(&cfg.server.data_dir) {
                Ok(r) => Arc::new(r),
                Err(e) => {
                    eprintln!("routelith server: cannot read the store: {e}");
                    return ExitCode::from(2);
                }
            };
            let tls = match &cfg.server.tls {
                None => None,
                Some(t) => match rl_web::tls_acceptor(&t.cert, &t.key) {
                    Ok(a) => Some(a),
                    Err(e) => {
                        eprintln!("routelith server: {e}");
                        return ExitCode::from(2);
                    }
                },
            };
            let auth = match rl_web::Auth::new(rl_web::AuthConfig {
                users_file: cfg.server.users_file.clone(),
                anonymous: cfg.server.anonymous,
                secure: tls.is_some(),
            }) {
                Ok(a) => Arc::new(a),
                Err(e) => {
                    eprintln!("routelith server: {e}");
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
            Some((addr, listener, reader, tls, auth))
        }
    };

    // The agent side (§21.7 G2): bind now too.
    let (agent_rounds_tx, agent_rounds_rx) = tokio::sync::mpsc::channel(64);
    let agents = match cfg.server.listen_agents {
        None => None,
        Some(addr) => {
            let mut opts = rl_fed::server::ServerOptions::new(
                addr,
                cfg.server.data_dir.clone(),
                env!("CARGO_PKG_VERSION"),
                &cfg.server.vantage,
            );
            opts.assignments = Arc::new(assignments(&plans[local_n..], &ids[local_n..]));
            opts.rounds = Some(agent_rounds_tx);
            opts.health = Some(spawn_health_writer(cfg.server.data_dir.clone()));
            match rl_fed::server::bind(opts).await {
                Ok(l) => Some(l),
                Err(e) => {
                    eprintln!("routelith server: {e}");
                    return ExitCode::from(2);
                }
            }
        }
    };

    // Alerts: the engine, its event log, and the state of the last run.
    let alert_series: Vec<crate::alerting::SeriesAlerts> = plans
        .iter()
        .zip(ids.iter().zip(&keys))
        .map(|(p, (&id, key))| crate::alerting::SeriesAlerts {
            id,
            key: key.clone(),
            step_ms: u64::try_from(p.schedule.step.as_millis()).unwrap_or(u64::MAX),
            rules: p.alerts.clone(),
        })
        .collect();
    // Silences: the configured ones and those added from the UI before.
    let silences = match rl_web::silences::Silences::load(
        cfg.silences.clone(),
        &cfg.server.data_dir,
        now_ms(),
    ) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("routelith server: {e}");
            return ExitCode::from(2);
        }
    };
    let alerting = match crate::alerting::start(&cfg, &alert_series, silences, now_ms()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("routelith server: {e}");
            return ExitCode::from(2);
        }
    };
    let board = alerting.board.clone();
    let output_stats = alerting.outputs.stats();

    let latest = Arc::new(Latest::default());
    let host = Arc::new(LatestHost::default());
    let store_stats = Arc::new(Mutex::new(StoreCounters::default()));
    let stats = Arc::new(Stats::default());
    let web = match ui {
        None => None,
        Some((addr, listener, reader, tls, auth)) => {
            let state = AppState {
                reader,
                data_dir: cfg.server.data_dir.clone(),
                host: host.clone(),
                series: series_infos(&plans, &ids),
                latest: latest.clone(),
                vantage: cfg.server.vantage.clone(),
                started: Instant::now(),
                extra_metrics: Some(extra_metrics(
                    stats.clone(),
                    store_stats.clone(),
                    output_stats.clone(),
                    agents.as_ref().map(|l| l.board.clone()),
                )),
                agents: agents
                    .as_ref()
                    .map(|l| -> Arc<dyn rl_web::agents::AgentAdmin> {
                        Arc::new(AgentsApi {
                            board: l.board.clone(),
                            registry: rl_fed::registry::Registry::new(&cfg.server.data_dir),
                            ca_sha256: l.ca_sha256,
                            vantage: cfg.server.vantage.clone(),
                        })
                    }),
                alerts: board.clone(),
                auth: auth.clone(),
                slas: cfg.slas.clone(),
                parents: crate::report::parents(&cfg),
            };
            Some((addr, listener, rl_web::router(Arc::new(state)), tls, auth))
        }
    };

    let (tx, rx) = mpsc::sync_channel::<Input>(QUEUE);
    // Tells the main loop when the store thread ends early (after an error).
    let (store_done_tx, mut store_done) = tokio::sync::oneshot::channel::<()>();
    let store_latest = latest.clone();
    let shared_counters = store_stats.clone();
    let store = std::thread::spawn(move || {
        let mut alerting = alerting;
        let r = store_loop(writer, &rx, &store_latest, &shared_counters, &mut alerting);
        let _ = store_done_tx.send(());
        r
    });
    // Agents' rounds wait for room in the queue instead of being dropped:
    // the agent keeps them until they are acknowledged.
    let remote_tx = tx.clone();
    let agent_feed = tokio::spawn(feed_agent_rounds(agent_rounds_rx, remote_tx));
    let event_tx = tx.clone();
    let sink: Sink = Arc::new(move |c| tx.try_send(Input::Local(c)).is_ok());
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

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut jobs = tokio::task::JoinSet::new();
    let local_ids: Vec<u64> = ids[..local_n].to_vec();
    for ((plan, series), probe) in plans
        .into_iter()
        .take(local_n)
        .zip(local_ids)
        .zip(plan_probes)
    {
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
    let web = web.map(|(addr, listener, router, tls, auth)| {
        let scheme = if tls.is_some() { "https" } else { "http" };
        eprintln!(
            "routelith server: web UI and API on {scheme}://{addr}/, {}",
            login_note(&auth)
        );
        if !addr.ip().is_loopback() && auth.users().is_empty() {
            eprintln!(
                "routelith server: warning: listen_ui {addr} is reachable from other hosts \
                 and there are no users, so anyone who can connect sees every target; \
                 add one with `routelith ctl user add`"
            );
        }
        let mut stop = stop_rx.clone();
        tokio::spawn(rl_web::serve(listener, router, tls, async move {
            let _ = stop.wait_for(|s| *s).await;
        }))
    });
    let agents = agents.map(|mut l| {
        eprintln!(
            "routelith server: agents connect to {} (CA fingerprint SHA-256 {}); \
             add one with `routelith ctl agent add <name>`",
            l.local_addr,
            rl_fed::fingerprint_text(&l.ca_sha256)
        );
        for note in &l.notes {
            eprintln!("routelith server: warning: {note}");
        }
        let events = l.take_events();
        (l, tokio::spawn(log_agent_events(events, event_tx)))
    });
    eprintln!(
        "routelith server: measuring {} series of {} targets from vantage {:?}, data in {}",
        jobs.len(),
        cfg.targets.len(),
        cfg.server.vantage,
        cfg.server.data_dir.display()
    );
    if agents.is_some() && !agent_names.is_empty() {
        eprintln!(
            "routelith server: agents measure {} series: {}",
            agent_series,
            agent_names.join(", ")
        );
    }

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
    if let Some((a, events)) = agents {
        a.shutdown();
        // It holds a store sender: the store ends only once it is gone.
        events.abort();
    }
    agent_feed.abort();
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
    /// Who measures it: the server's own vantage or an agent.
    vantage: String,
    target: String,
    host: String,
    family: Family,
    group: String,
    schedule: rl_core::config::Schedule,
    probe: ProbeConfig,
    /// Alert rules that apply.
    alerts: Vec<String>,
}

/// One probe instance per distinct probe configuration, all sharing the
/// packets-per-second ceiling.
pub(crate) fn make_probe(
    cfg: &ProbeConfig,
    limiter: &Arc<RateLimiter>,
) -> Result<Arc<dyn Probe>, ProbeError> {
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

/// Targets as series: a `both` target measures v4 and v6 separately. The
/// server's own series come first, then each agent's.
fn series_plans(cfg: &Config, agents: &[String]) -> Vec<SeriesPlan> {
    let mut out = Vec::new();
    let own = &cfg.server.vantage;
    let mut add = |vantage: &str, t: &rl_core::config::TargetConfig| {
        let families: &[Family] = match t.family {
            Family::Both => &[Family::V4, Family::V6],
            Family::V4 => &[Family::V4],
            Family::V6 => &[Family::V6],
            Family::PreferV6 => &[Family::PreferV6],
        };
        for &family in families {
            out.push(SeriesPlan {
                vantage: vantage.to_string(),
                target: t.id.clone(),
                host: t.host.clone(),
                group: t.group.clone(),
                family,
                schedule: t.schedule,
                probe: t.probe.clone(),
                alerts: t.alerts.clone(),
            });
        }
    };
    for t in &cfg.targets {
        add(own, t);
    }
    for agent in agents {
        for t in cfg
            .agent_targets
            .iter()
            .filter(|t| t.measured_by(agent, own))
        {
            add(agent, t);
        }
    }
    out
}

/// The agents that measure something: those named in `vantages`, and with
/// `"*"` every enrolled, unrevoked agent. Sorted, without the server.
fn agent_vantages(cfg: &Config) -> Result<Vec<String>, String> {
    if cfg.server.listen_agents.is_none() {
        return Ok(Vec::new());
    }
    let own = &cfg.server.vantage;
    let mut names: std::collections::BTreeSet<String> = cfg
        .agent_targets
        .iter()
        .flat_map(|t| t.vantages.iter())
        .filter(|v| *v != own && *v != config::ALL_VANTAGES)
        .cloned()
        .collect();
    let everyone = cfg
        .agent_targets
        .iter()
        .any(|t| t.vantages.iter().any(|v| v == config::ALL_VANTAGES));
    if everyone {
        let enrolled = rl_fed::registry::Registry::new(&cfg.server.data_dir)
            .list()
            .map_err(|e| e.to_string())?;
        names.extend(
            enrolled
                .into_iter()
                .filter(|a| a.revoked_ms.is_none() && &a.name != own)
                .map(|a| a.name),
        );
    }
    Ok(names.into_iter().collect())
}

/// What each agent measures, from its plans and their series ids.
fn assignments(plans: &[SeriesPlan], ids: &[u64]) -> rl_fed::assign::Assignments {
    let mut by_agent: HashMap<&str, Vec<rl_fed::pb::Assignment>> = HashMap::new();
    for (p, &id) in plans.iter().zip(ids) {
        let spec = rl_fed::assign::Spec {
            host: p.host.clone(),
            family: p.family,
            schedule: p.schedule,
            probe: p.probe.clone(),
        };
        by_agent
            .entry(&p.vantage)
            .or_default()
            .push(rl_fed::assign::assignment(id, &p.target, &spec));
    }
    let mut out = rl_fed::assign::Assignments::default();
    for (agent, list) in by_agent {
        out.insert(agent, list);
    }
    out
}

/// What the store thread takes: a round measured here, or one an agent
/// measured (already in stored form), or a request to be told once
/// everything before it is synced to disk.
enum Input {
    Local(Completed),
    Remote {
        series: u64,
        round: StoredRound,
        latest: LatestRound,
    },
    Synced(tokio::sync::oneshot::Sender<Result<(), String>>),
    /// An event about an agent (§21.7 G10), for the event log.
    Event(rl_store::Event),
}

/// An agent event as the event log keeps it, if it goes there.
fn agent_event(e: &rl_fed::server::AgentEvent, now_ms: i64) -> Option<rl_store::Event> {
    use rl_fed::server::AgentEvent as A;
    use rl_store::EventKind as K;
    let (kind, t, value) = match e {
        A::Enrolled { .. } => (K::AgentEnrolled, now_ms, None),
        A::Up { .. } => (K::AgentConnected, now_ms, None),
        A::Down { since_ms, .. } => (K::AgentDisconnected, *since_ms, None),
        A::Revoked { .. } => (K::AgentRevoked, now_ms, None),
        A::ClockSkewed { offset_ms, .. } => (K::AgentClockSkew, now_ms, Some(offset_ms.round())),
        A::ClockOk { offset_ms, .. } => (K::AgentClockOk, now_ms, Some(offset_ms.round())),
        #[allow(clippy::cast_precision_loss)]
        A::RoundsLost { rounds, .. } => (K::AgentRoundsLost, now_ms, Some(*rounds as f64)),
        _ => return None,
    };
    let mut ev = rl_store::Event::new(t, kind, e.agent()?, e.to_string());
    ev.value = value;
    Some(ev)
}

/// Log every agent event, and hand those that belong in the event log to
/// the store thread.
async fn log_agent_events(
    mut rx: tokio::sync::mpsc::Receiver<rl_fed::server::AgentEvent>,
    tx: mpsc::SyncSender<Input>,
) {
    while let Some(e) = rx.recv().await {
        match agent_event(&e, now_ms()) {
            Some(ev) => {
                let tx = tx.clone();
                let sent =
                    tokio::task::spawn_blocking(move || tx.send(Input::Event(ev)).is_ok()).await;
                if !matches!(sent, Ok(true)) {
                    return;
                }
            }
            // The store thread says these.
            None => eprintln!("routelith server: {e}"),
        }
    }
}

/// Store agents' health snapshots (§21.7 G10) under their names, as the
/// server's own are under its vantage.
fn spawn_health_writer(
    data_dir: PathBuf,
) -> tokio::sync::mpsc::Sender<rl_fed::server::AgentHealth> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<rl_fed::server::AgentHealth>(64);
    std::thread::spawn(move || {
        let mut logs: HashMap<String, rl_store::health::HealthLog> = HashMap::new();
        let mut last_error: Option<String> = None;
        while let Some(h) = rx.blocking_recv() {
            let result = serde_json::from_slice::<rl_store::health::HealthSample>(&h.sample_json)
                .map_err(|e| format!("agent {}: invalid health snapshot: {e}", h.agent))
                .and_then(|sample| {
                    let log = match logs.entry(h.agent.clone()) {
                        std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                        std::collections::hash_map::Entry::Vacant(v) => v.insert(
                            rl_store::health::HealthLog::open(
                                &data_dir,
                                &h.agent,
                                crate::health::KEEP_DAYS,
                            )
                            .map_err(|e| format!("agent {}: {e}", h.agent))?,
                        ),
                    };
                    log.append(&sample)
                        .map_err(|e| format!("agent {}: {e}", h.agent))
                });
            if let Err(msg) = result {
                if last_error.as_deref() != Some(msg.as_str()) {
                    eprintln!("routelith server: cannot store a health snapshot: {msg}");
                    last_error = Some(msg);
                }
            }
        }
    });
    tx
}

/// The agents in the API (§21.7 G12): every enrolled agent and every one
/// seen since the start, with what the server knows of it now; and
/// enrollment and revocation for admins.
struct AgentsApi {
    board: Arc<rl_fed::status::Board>,
    registry: rl_fed::registry::Registry,
    ca_sha256: [u8; 32],
    /// The server's own vantage, which no agent may take.
    vantage: String,
}

impl rl_web::agents::AgentAdmin for AgentsApi {
    fn list(&self) -> serde_json::Value {
        let records = self.registry.list().unwrap_or_default();
        let mut live: HashMap<String, rl_fed::status::AgentStatus> = self
            .board
            .snapshot()
            .into_iter()
            .map(|s| (s.name.clone(), s))
            .collect();
        let mut out = Vec::new();
        let mut names: Vec<String> = records.iter().map(|r| r.name.clone()).collect();
        names.extend(
            live.keys()
                .filter(|n| !records.iter().any(|r| &r.name == *n))
                .cloned(),
        );
        names.sort();
        for name in names {
            let rec = records.iter().find(|r| r.name == name);
            let s = live
                .remove(&name)
                .unwrap_or_else(|| rl_fed::status::AgentStatus {
                    name: name.clone(),
                    ..Default::default()
                });
            out.push(serde_json::json!({
                "name": name,
                "enrolled_ms": rec.map(|r| r.enrolled_ms),
                "cert_expires_ms": rec.map(|r| r.cert_expires_ms),
                "revoked_ms": rec.and_then(|r| r.revoked_ms),
                "connected": s.connected,
                "addr": s.addr.map(|a| a.to_string()),
                "version": if s.version.is_empty() { rec.map(|r| r.version.clone()) } else { Some(s.version.clone()) },
                "os": (!s.os.is_empty()).then_some(s.os.clone()),
                "capabilities": s.capabilities,
                "connected_ms": s.connected_ms,
                "last_seen_ms": s.last_seen_ms,
                "clock_offset_ms": s.clock_offset_ms,
                "clock_delay_ms": s.clock_delay_ms,
                "clock_skewed": s.clock_skewed,
                "timing": s.timing.iter()
                    .filter_map(|&c| rl_core::TimingBackend::from_code(c))
                    .map(rl_core::TimingBackend::describe)
                    .collect::<Vec<_>>(),
                "spool_bytes": s.spool_bytes,
                "spool_backlog": s.spool_backlog,
                "rounds_lost": s.rounds_lost,
                "refused": s.refused.iter()
                    .map(|(id, why)| serde_json::json!({"series": id, "reason": why}))
                    .collect::<Vec<_>>(),
            }));
        }
        let now = now_ms();
        let tokens: Vec<serde_json::Value> = self
            .registry
            .pending_tokens(now)
            .unwrap_or_default()
            .into_iter()
            .map(|t| serde_json::json!({ "name": t.name, "expires_ms": t.expires_ms }))
            .collect();
        serde_json::json!({ "agents": out, "tokens": tokens })
    }

    fn add_token(&self, name: &str) -> Result<(String, i64), (rl_web::StatusCode, String)> {
        let bad = |m: String| (rl_web::StatusCode::BAD_REQUEST, m);
        rl_fed::registry::check_name(name).map_err(|e| bad(e.to_string()))?;
        if name == self.vantage {
            return Err(bad(format!("{name:?} is the server's own vantage name")));
        }
        let now = now_ms();
        let secret = self
            .registry
            .add_token(name, rl_fed::registry::TOKEN_TTL_MS, now)
            .map_err(|e| match e {
                rl_fed::FedError::Invalid(m) => bad(m),
                e => (rl_web::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            })?;
        let token = rl_fed::token::Token {
            secret,
            ca_sha256: self.ca_sha256,
        };
        eprintln!("routelith server: an enrollment token for agent {name} was made in the web UI");
        Ok((token.encode(), now + rl_fed::registry::TOKEN_TTL_MS))
    }

    fn revoke(&self, name: &str) -> Result<(), (rl_web::StatusCode, String)> {
        rl_fed::registry::check_name(name)
            .map_err(|e| (rl_web::StatusCode::BAD_REQUEST, e.to_string()))?;
        match self.registry.revoke(name, now_ms()) {
            Ok(true) => {
                eprintln!("routelith server: agent {name} was revoked in the web UI");
                Ok(())
            }
            Ok(false) => Err((
                rl_web::StatusCode::NOT_FOUND,
                format!("no agent named {name}"),
            )),
            Err(e) => Err((rl_web::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }
}

/// Move agents' batches into the store queue, waiting for room (on a
/// blocking thread, as the queue is a std channel).
async fn feed_agent_rounds(
    mut rx: tokio::sync::mpsc::Receiver<rl_fed::server::AgentRounds>,
    tx: mpsc::SyncSender<Input>,
) {
    while let Some(batch) = rx.recv().await {
        let tx = tx.clone();
        let result = tokio::task::spawn_blocking(move || {
            for r in &batch.rounds {
                let round = match rl_fed::assign::from_wire(r) {
                    Ok(round) => round,
                    Err(e) => {
                        eprintln!(
                            "routelith server: agent {}: series {}: invalid round: {e}",
                            batch.agent, r.series_id
                        );
                        continue;
                    }
                };
                let latest = remote_latest(&round, r.http.as_ref());
                if tx
                    .send(Input::Remote {
                        series: r.series_id,
                        round,
                        latest,
                    })
                    .is_err()
                {
                    let _ = batch.done.send(Err("the store has stopped".to_string()));
                    return;
                }
            }
            // The agent gets its Ack once the rounds are synced (G7).
            if let Err(mpsc::SendError(Input::Synced(done))) = tx.send(Input::Synced(batch.done)) {
                let _ = done.send(Err("the store has stopped".to_string()));
            }
        })
        .await;
        if result.is_err() {
            return;
        }
    }
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

/// How callers get in, for the start-up line.
fn login_note(auth: &rl_web::Auth) -> String {
    let n = auth.users().users.len();
    let file = auth.config().users_file.display();
    match (n, auth.config().anonymous) {
        (0, _) => format!("no login (no users in {file})"),
        (n, false) => format!(
            "login required ({n} user{} in {file})",
            if n == 1 { "" } else { "s" }
        ),
        (n, true) => format!(
            "anonymous read-only, login to change things ({n} user{} in {file})",
            if n == 1 { "" } else { "s" }
        ),
    }
}

/// The stored form of a finished round. A round that could not run counts
/// every sample as an error of its cause.
pub(crate) fn stored(c: &Completed) -> Result<StoredRound, rl_store::StoreError> {
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
    rx: &mpsc::Receiver<Input>,
    latest: &Latest,
    counters: &Mutex<StoreCounters>,
    alerting: &mut Alerting,
) -> Result<u64, rl_store::StoreError> {
    let (mut late, mut rejected) = (0u64, 0u64);
    let result = store_rounds(
        &mut w,
        rx,
        latest,
        counters,
        alerting,
        &mut late,
        &mut rejected,
    );
    if late > 0 {
        eprintln!(
            "routelith server: store: {late} round(s) were not newer than the last one and were dropped"
        );
    }
    match result.and_then(|()| w.close()) {
        Ok(()) => alerting.stopped(now_ms()),
        Err(e) => {
            // Still hand on what is queued, as an exit cuts the outputs off.
            alerting.close_outputs();
            return Err(e);
        }
    }
    Ok(rejected)
}

fn store_rounds(
    w: &mut Writer,
    rx: &mpsc::Receiver<Input>,
    latest: &Latest,
    counters: &Mutex<StoreCounters>,
    alerting: &mut Alerting,
    late: &mut u64,
    rejected: &mut u64,
) -> Result<(), rl_store::StoreError> {
    let mut next_sync = Instant::now() + SYNC_EVERY;
    let mut last_invalid: Option<String> = None;
    // Waiting for the next sync; dropped unanswered if the store fails.
    let mut synced: Vec<tokio::sync::oneshot::Sender<Result<(), String>>> = Vec::new();
    loop {
        let wait = next_sync.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(Input::Synced(done)) => synced.push(done),
            Ok(Input::Event(e)) => alerting.event(e),
            Ok(input) => match append(w, input) {
                (series, Ok((Appended::Stored, newest, r))) => {
                    latest.record(series, newest);
                    alerting.round(series, &r);
                }
                (_, Ok((Appended::Late, _, _))) => *late += 1,
                (series, Err(rl_store::StoreError::InvalidRound(msg))) => {
                    *rejected += 1;
                    if last_invalid.as_deref() != Some(msg) {
                        eprintln!("routelith server: store: series {series}: invalid round: {msg}");
                        last_invalid = Some(msg.to_string());
                    }
                }
                (_, Err(e)) => return Err(e),
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        if Instant::now() >= next_sync {
            next_sync += SYNC_EVERY;
            w.sync()?;
            for done in synced.drain(..) {
                let _ = done.send(Ok(()));
            }
            w.maintain(now_ms())?;
            *counters.lock().unwrap_or_else(PoisonError::into_inner) = StoreCounters {
                writer: w.stats(),
                wal_bytes: w.wal_bytes(),
                rejected: *rejected,
                event_errors: alerting.write_errors,
            };
        }
    }
}

/// Append one input round. Returns its series and, when it was taken,
/// how, with the newest-round summary and the round for the alerts.
fn append(
    w: &mut Writer,
    input: Input,
) -> (
    u64,
    Result<(Appended, LatestRound, StoredRound), rl_store::StoreError>,
) {
    let (series, prepared) = match input {
        Input::Local(c) => (
            c.series,
            stored(&c).map(|r| {
                let newest = latest_round(&c, &r);
                (r, newest)
            }),
        ),
        Input::Remote {
            series,
            round,
            latest,
        } => (series, Ok((round, latest))),
        Input::Synced(_) | Input::Event(_) => {
            unreachable!("store_rounds handles sync requests and events itself")
        }
    };
    // The writer takes the round; alerts need it after.
    let result =
        prepared.and_then(|(r, newest)| w.append(series, r.clone()).map(|a| (a, newest, r)));
    (series, result)
}

/// What `/metrics` shows of the store, refreshed once a second.
#[derive(Debug, Clone, Copy, Default)]
struct StoreCounters {
    writer: WriterStats,
    wal_bytes: u64,
    rejected: u64,
    /// Events the event log could not take.
    event_errors: u64,
}

/// The API's view of the series.
fn series_infos(plans: &[SeriesPlan], ids: &[u64]) -> Vec<SeriesInfo> {
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
                key: SeriesKey::new(&p.vantage, &p.target, p.family.as_str()),
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

/// The median as SmokePing (and alert rules) take it: the mean of the two
/// middle values for an even count.
fn median(sorted: &[u32]) -> Option<u32> {
    let n = sorted.len();
    match n {
        0 => None,
        _ if n % 2 == 1 => Some(sorted[n / 2]),
        _ => u32::try_from((u64::from(sorted[n / 2 - 1]) + u64::from(sorted[n / 2])) / 2).ok(),
    }
}

/// The newest round as `/metrics` shows it.
/// The newest-round summary of a round an agent measured.
fn remote_latest(r: &StoredRound, http: Option<&rl_fed::pb::HttpSummary>) -> LatestRound {
    let mut l = summary(r);
    if let Some(h) = http {
        l.http_phases_us = Some(HttpPhases {
            connect: h.connect_us,
            tls: h.tls_us,
            ttfb: h.ttfb_us,
            total: h.total_us,
        });
        l.cert_not_after_s = h.cert_not_after_s;
    }
    l
}

/// The parts of the newest-round summary that come from the stored round.
fn summary(r: &StoredRound) -> LatestRound {
    let q = |p: usize| nearest_rank(&r.rtts_us, p);
    LatestRound {
        ts_ms: r.ts_ms,
        sent: u32::from(r.sent),
        received: u32::try_from(r.rtts_us.len()).unwrap_or(u32::MAX),
        min_us: q(0),
        median_us: median(&r.rtts_us),
        p90_us: q(90),
        max_us: q(100),
        errors: r.errors.total(),
        http_phases_us: None,
        cert_not_after_s: None,
    }
}

/// HTTP phase medians and certificate expiry of a measured round.
pub(crate) fn http_summary(c: &Completed) -> Option<(HttpPhases, Option<i64>)> {
    let http = match &c.outcome {
        Outcome::Measured(m) => m.http.as_ref(),
        Outcome::Failed { .. } => None,
    }?;
    let done: Vec<&rl_core::round::PhaseTimings> = http.phases.iter().flatten().collect();
    let median = |f: &dyn Fn(&rl_core::round::PhaseTimings) -> Option<u32>| {
        let mut v: Vec<u32> = done.iter().filter_map(|p| f(p)).collect();
        v.sort_unstable();
        (!v.is_empty()).then(|| v[(v.len() - 1) / 2])
    };
    let phases = HttpPhases {
        connect: median(&|p| Some(p.connect_us)),
        tls: median(&|p| p.tls_us),
        ttfb: median(&|p| Some(p.ttfb_us)),
        total: median(&|p| Some(p.total_us)),
    };
    Some((
        phases,
        http.cert_not_after.map(|t| to_ms(t).div_euclid(1000)),
    ))
}

fn latest_round(c: &Completed, r: &StoredRound) -> LatestRound {
    let mut l = summary(r);
    if let Some((phases, cert)) = http_summary(c) {
        l.http_phases_us = Some(phases);
        l.cert_not_after_s = cert;
    }
    l
}

/// Scheduler and store counters for `/metrics`.
fn extra_metrics(
    stats: Arc<Stats>,
    store: Arc<Mutex<StoreCounters>>,
    outputs: Vec<Arc<rl_out::OutputStats>>,
    agents: Option<Arc<rl_fed::status::Board>>,
) -> rl_web::ExtraMetrics {
    Arc::new(move |m: &mut MetricsWriter| {
        let s = stats.snapshot(false);
        let st = *store.lock().unwrap_or_else(PoisonError::into_inner);
        #[allow(clippy::cast_precision_loss)]
        let counters: [(&str, &str, u64); 12] = [
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
            (
                "routelith_event_log_errors_total",
                "Events (alerts, address changes) that could not be written to the event log.",
                st.event_errors,
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
        output_metrics(m, &outputs);
        if let Some(board) = &agents {
            agent_metrics(m, &board.snapshot());
        }
    })
}

/// Per-agent gauges (§21.7 G10, G12), labelled with the agent's name.
fn agent_metrics(m: &mut MetricsWriter, agents: &[rl_fed::status::AgentStatus]) {
    m.family(
        "routelith_agent_connected",
        "gauge",
        "Whether the agent is connected now (1) or not (0).",
    );
    for a in agents {
        m.sample(
            "routelith_agent_connected",
            &[("agent", &a.name)],
            if a.connected { 1.0 } else { 0.0 },
        );
    }
    m.family(
        "routelith_agent_clock_offset_seconds",
        "gauge",
        "Agent clock minus server clock.",
    );
    for a in agents {
        if let Some(ms) = a.clock_offset_ms {
            m.sample(
                "routelith_agent_clock_offset_seconds",
                &[("agent", &a.name)],
                ms / 1000.0,
            );
        }
    }
    m.family(
        "routelith_agent_spool_bytes",
        "gauge",
        "Bytes of rounds in the agent's spool.",
    );
    for a in agents {
        if let Some(b) = a.spool_bytes {
            #[allow(clippy::cast_precision_loss)]
            m.sample(
                "routelith_agent_spool_bytes",
                &[("agent", &a.name)],
                b as f64,
            );
        }
    }
    m.family(
        "routelith_agent_rounds_lost_total",
        "counter",
        "Rounds the agent measured that never arrived, since the server started.",
    );
    for a in agents {
        #[allow(clippy::cast_precision_loss)]
        m.sample(
            "routelith_agent_rounds_lost_total",
            &[("agent", &a.name)],
            a.rounds_lost as f64,
        );
    }
}

/// Per-output counters (§21.5 F7), labelled with the output's name and type.
fn output_metrics(m: &mut MetricsWriter, outputs: &[Arc<rl_out::OutputStats>]) {
    use std::sync::atomic::Ordering::Relaxed;
    if outputs.is_empty() {
        return;
    }
    type Get = fn(&rl_out::OutputStats) -> u64;
    let families: [(&str, &str, &str, Get); 5] = [
        (
            "routelith_output_events_sent_total",
            "counter",
            "Events an output delivered.",
            |o| o.sent.load(Relaxed),
        ),
        (
            "routelith_output_events_dropped_total",
            "counter",
            "Events an output dropped: its queue was full, or the server stopped first.",
            |o| o.dropped.load(Relaxed),
        ),
        (
            "routelith_output_errors_total",
            "counter",
            "Failed delivery attempts of an output (each retry counts).",
            |o| o.errors.load(Relaxed),
        ),
        (
            "routelith_output_queue_length",
            "gauge",
            "Events waiting in an output's queue.",
            |o| o.queued.load(Relaxed),
        ),
        (
            "routelith_output_up",
            "gauge",
            "1 unless the output's last delivery attempt failed.",
            |o| u64::from(o.up.load(Relaxed)),
        ),
    ];
    for (name, kind, help, get) in families {
        m.family(name, kind, help);
        for o in outputs {
            #[allow(clippy::cast_precision_loss)]
            m.sample(
                name,
                &[("output", &o.name), ("type", o.kind)],
                get(o) as f64,
            );
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
pub(crate) fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
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
        let fams: Vec<_> = series_plans(&cfg, &[])
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
    fn agent_events_reach_the_event_log_with_their_values() {
        use rl_fed::server::AgentEvent as A;
        use rl_store::EventKind as K;
        let e = agent_event(
            &A::ClockSkewed {
                name: "genk".into(),
                offset_ms: 150.4,
            },
            1_000,
        )
        .unwrap();
        assert_eq!(
            (e.kind, e.t, e.value),
            (K::AgentClockSkew, 1_000, Some(150.0))
        );
        assert_eq!(e.vantage, "genk");
        assert!(e.series.is_none() && e.target.is_none());
        let e = agent_event(
            &A::Down {
                name: "genk".into(),
                since_ms: 400,
            },
            1_000,
        )
        .unwrap();
        assert_eq!((e.kind, e.t), (K::AgentDisconnected, 400));
        let e = agent_event(
            &A::RoundsLost {
                name: "genk".into(),
                rounds: 7,
            },
            1_000,
        )
        .unwrap();
        assert_eq!(e.value, Some(7.0));
        // Per-connection news stays in the server's log.
        assert!(
            agent_event(
                &A::Connected {
                    name: "genk".into(),
                    addr: "192.0.2.7:1".parse().unwrap(),
                    version: "1".into(),
                    os: "linux".into(),
                },
                1_000,
            )
            .is_none()
        );
    }

    #[test]
    fn agent_gauges_carry_the_agents_name() {
        let mut m = MetricsWriter::default();
        agent_metrics(
            &mut m,
            &[rl_fed::status::AgentStatus {
                name: "genk".into(),
                connected: true,
                clock_offset_ms: Some(-12.0),
                spool_bytes: Some(4096),
                ..Default::default()
            }],
        );
        let text = m.finish();
        assert!(
            text.contains("routelith_agent_connected{agent=\"genk\"} 1"),
            "{text}"
        );
        assert!(text.contains("routelith_agent_clock_offset_seconds{agent=\"genk\"} -0.012"));
        assert!(text.contains("routelith_agent_spool_bytes{agent=\"genk\"} 4096"));
    }

    #[test]
    fn agents_get_their_own_series_after_the_servers() {
        let dir = tempfile::tempdir().unwrap();
        let src = format!(
            "[server]\ndata_dir = {:?}\nvantage = \"home\"\nlisten_agents = \"127.0.0.1:0\"\n\
             [[group]]\nname = \"g\"\nvantages = [\"home\", \"genk\"]\n\
             [[group.target]]\nname = \"a\"\nhost = \"h\"\n\
             [[group]]\nname = \"all\"\nvantages = [\"*\"]\n\
             [[group.target]]\nname = \"b\"\nhost = \"h\"\nfamily = \"both\"\n",
            dir.path().display().to_string()
        );
        let parsed = config::parse(&src);
        let cfg = parsed.config.expect("valid config");
        // "*" takes in enrolled agents that are not revoked.
        let reg = rl_fed::registry::Registry::new(dir.path());
        for (name, revoked) in [("gent", None), ("old", Some(1))] {
            reg.save(&rl_fed::registry::AgentRecord {
                name: name.into(),
                cert_sha256: name.into(),
                enrolled_ms: 0,
                cert_expires_ms: 0,
                version: String::new(),
                revoked_ms: revoked,
            })
            .unwrap();
        }
        let agents = agent_vantages(&cfg).unwrap();
        assert_eq!(agents, ["genk", "gent"]);
        let plans = series_plans(&cfg, &agents);
        let got: Vec<_> = plans
            .iter()
            .map(|p| format!("{}/{}/{}", p.vantage, p.target, p.family.as_str()))
            .collect();
        assert_eq!(
            got,
            [
                "home/a/v4",
                "home/b/v4",
                "home/b/v6",
                "genk/a/v4",
                "genk/b/v4",
                "genk/b/v6",
                "gent/b/v4",
                "gent/b/v6"
            ]
        );
        let ids: Vec<u64> = (1..=8).collect();
        let a = assignments(&plans[3..], &ids[3..]);
        assert!(a.owns("genk", 4) && a.owns("genk", 6) && !a.owns("genk", 7));
        assert!(a.owns("gent", 7) && !a.owns("gent", 1));
        assert_eq!(a.snapshot("genk").assignments.len(), 3);
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
    fn the_median_of_an_even_round_is_the_middle_pair_mean() {
        assert_eq!(median(&[1000, 39_000]), Some(20_000));
        assert_eq!(median(&[100, 200, 300]), Some(200));
        assert_eq!(median(&[]), None);
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
        tx.send(Input::Local(failed(284_000_000_000))).unwrap();
        tx.send(Input::Local(failed(1_800_000_000))).unwrap();
        drop(tx);
        let latest = Latest::default();
        let counters = Mutex::new(StoreCounters::default());
        let src = format!(
            "[server]\ndata_dir = {:?}\n[[group]]\nname = \"g\"\n[[group.target]]\nname = \"t\"\nhost = \"192.0.2.1\"\n",
            dir.path().display().to_string()
        );
        let cfg = config::parse(&src).config.unwrap();
        let mut alerting = crate::alerting::start(
            &cfg,
            &[],
            Arc::new(rl_web::silences::Silences::configured(Vec::new())),
            0,
        )
        .unwrap();
        assert_eq!(
            store_loop(w, &rx, &latest, &counters, &mut alerting).unwrap(),
            1
        );
        let rounds = rl_store::Reader::open(dir.path())
            .unwrap()
            .read(id, 0, i64::MAX)
            .unwrap();
        assert_eq!(rounds.len(), 1);
        assert_eq!(rounds[0].ts_ms, 1_800_000_000_000);
    }
}
