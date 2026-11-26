//! Agents (§21.7): `routelith agent enroll|run` on the agent, and
//! `routelith ctl agent add|list|revoke` on the server.

use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use rl_core::config::{self, Family, ProbeConfig};
use rl_fed::agent_config::AgentConfig;
use rl_fed::allow::{AllowList, Verdict};
use rl_fed::ca::Ca;
use rl_fed::client::{self, Identity};
use rl_fed::pb;
use rl_fed::registry::{Registry, TOKEN_TTL_MS};
use rl_fed::spool::{Dropped, Spool, spool_dir};
use rl_fed::token::Token;
use rl_probe::{Probe, RateLimiter};
use rl_sched::{Completed, Job, Sink, Stats};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Subcommand)]
pub(crate) enum AgentAction {
    /// Enroll this agent with a server, using a token from
    /// `routelith ctl agent add` on the server.
    Enroll {
        /// The agent's configuration file (server address, data_dir).
        #[arg(short, long)]
        config: PathBuf,
        /// The enrollment token (rlt1-…).
        #[arg(long, conflicts_with = "token_stdin")]
        token: Option<String>,
        /// Read the token from the first line of standard input instead.
        #[arg(long)]
        token_stdin: bool,
    },
    /// Measure what the server assigns and send it the rounds,
    /// reconnecting after failures.
    Run {
        /// The agent's configuration file.
        #[arg(short, long)]
        config: PathBuf,
    },
}

pub(crate) fn agent(action: AgentAction) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("routelith agent: cannot start: {e}");
            return ExitCode::from(2);
        }
    };
    match action {
        AgentAction::Enroll {
            config,
            token,
            token_stdin,
        } => rt.block_on(enroll(&config, token, token_stdin)),
        AgentAction::Run { config } => rt.block_on(run(&config)),
    }
}

async fn enroll(path: &Path, token: Option<String>, from_stdin: bool) -> ExitCode {
    let cfg = match AgentConfig::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("routelith agent: {e}");
            return ExitCode::from(1);
        }
    };
    let text = match (token, from_stdin) {
        (Some(t), _) => t,
        (None, true) => {
            let mut line = String::new();
            if let Err(e) = std::io::stdin().lock().read_line(&mut line) {
                eprintln!("routelith agent: cannot read standard input: {e}");
                return ExitCode::from(2);
            }
            line
        }
        (None, false) => {
            eprintln!("routelith agent: give the token with --token or --token-stdin");
            return ExitCode::from(1);
        }
    };
    let token = match Token::parse(&text) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("routelith agent: {e}");
            return ExitCode::from(1);
        }
    };
    match client::enroll(&cfg.server, &token, &cfg.data_dir, VERSION).await {
        Ok(name) => {
            println!(
                "enrolled with {} as agent {name}; identity saved in {}",
                cfg.server,
                client::identity_dir(&cfg.data_dir).display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("routelith agent: enrollment failed: {e}");
            ExitCode::from(2)
        }
    }
}

async fn run(path: &Path) -> ExitCode {
    let signal = match crate::server::shutdown_signal() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("routelith agent: cannot listen for shutdown signals: {e}");
            return ExitCode::from(2);
        }
    };
    serve(path, signal).await
}

/// Run the agent until `signal` completes (Ctrl-C, or the Windows service
/// manager's stop request).
pub(crate) async fn serve(path: &Path, signal: impl std::future::Future<Output = ()>) -> ExitCode {
    let cfg = match AgentConfig::load(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("routelith agent: {e}");
            return ExitCode::from(1);
        }
    };
    let id = match Identity::load(&cfg.data_dir) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("routelith agent: {e}");
            return ExitCode::from(1);
        }
    };
    let dir = spool_dir(&cfg.data_dir);
    let spool = match Spool::open(&dir, cfg.spool, rl_fed::now_ms()) {
        Ok((s, opened)) => {
            for note in opened.notes {
                eprintln!("routelith agent: spool: {note}");
            }
            s
        }
        Err(e) => {
            eprintln!("routelith agent: spool: {e}");
            return ExitCode::from(2);
        }
    };
    if spool.backlog() > 0 {
        eprintln!(
            "routelith agent: {} round(s) in {} wait for the server",
            spool.backlog(),
            dir.display()
        );
    }
    let capabilities = capabilities();
    eprintln!(
        "routelith agent: {} connecting to {}; can measure {}",
        id.name,
        cfg.server,
        capabilities.join(", ")
    );
    // Health snapshots (§21.7 G10), once a minute on the minute.
    let (health_tx, mut health_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let (health_stop, health_stop_rx) = std::sync::mpsc::channel::<()>();
    let health = std::thread::Builder::new()
        .name("health".into())
        .spawn(move || {
            crate::health::every_minute(&health_stop_rx, rl_fed::now_ms, |s, _| {
                if let Ok(json) = serde_json::to_vec(&s) {
                    // Kept while disconnected until the queue is full.
                    let _ = health_tx.try_send(json);
                }
            });
        });
    if let Err(e) = &health {
        eprintln!("routelith agent: warning: no health snapshots: {e}");
    }
    tokio::pin!(signal);
    let outbox = Arc::new(Outbox::new(spool));
    let mut m = Measuring::new(&id.name, cfg.max_pps, outbox.clone());
    m.allow = Arc::new(cfg.allow.clone());
    let mut backoff = Backoff::default();
    loop {
        let started = Instant::now();
        let attempt = async {
            match client::connect(&cfg.server, &id, VERSION, outbox.intro(&capabilities)).await {
                Ok(s) => {
                    eprintln!(
                        "routelith agent: connected to {} as {} (server version {})",
                        cfg.server, s.name, s.server_version
                    );
                    let why = session(s, &mut m, &outbox, &mut health_rx).await;
                    eprintln!("routelith agent: disconnected: {why}");
                }
                Err(e) => eprintln!("routelith agent: {e}"),
            }
        };
        tokio::select! {
            () = &mut signal => break,
            () = attempt => {
                outbox.report_drops();
                let wait = backoff.next(started.elapsed());
                eprintln!("routelith agent: trying again in {} s", wait.as_secs());
                tokio::select! {
                    () = &mut signal => break,
                    () = tokio::time::sleep(wait) => {}
                }
            }
        }
    }
    eprintln!("routelith agent: stopping");
    drop(health_stop);
    m.stop().await;
    let mut spool = outbox.lock();
    if let Err(e) = spool.sync() {
        eprintln!("routelith agent: spool: {e}");
    }
    if spool.backlog() > 0 {
        eprintln!(
            "routelith agent: {} round(s) stay in the spool for next time",
            spool.backlog()
        );
    }
    let failed = outbox.failed.load(Ordering::Relaxed);
    if failed > 0 {
        eprintln!(
            "routelith agent: {failed} round(s) were lost because the spool could not be written"
        );
    }
    ExitCode::SUCCESS
}

/// Rounds per batch at most; a batch also goes out 1 s after its first
/// round. Replays after an outage send larger batches.
const BATCH: usize = 500;
const REPLAY_BATCH: usize = 5_000;
/// Encoded size per batch at most (gRPC refuses messages over 4 MiB).
const BATCH_BYTES: usize = 1 << 20;
/// Rounds sent and not yet acknowledged at most.
const WINDOW: u64 = 10_000;

/// The spool and what the measuring jobs and the stream share about it.
struct Outbox {
    spool: Mutex<Spool>,
    /// Woken when a round is spooled.
    ready: tokio::sync::Notify,
    /// Rounds the spool could not take.
    failed: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// Drops by the spool's bounds already reported.
    reported: Mutex<Dropped>,
}

impl Outbox {
    fn new(spool: Spool) -> Self {
        Outbox {
            spool: Mutex::new(spool),
            ready: tokio::sync::Notify::new(),
            failed: AtomicU64::new(0),
            last_error: Mutex::new(None),
            reported: Mutex::new(Dropped::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Spool> {
        self.spool.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn intro(&self, capabilities: &[String]) -> client::Intro {
        let s = self.lock();
        client::Intro {
            spool_id: s.id(),
            acked_seq: s.acked(),
            capabilities: capabilities.to_vec(),
        }
    }

    /// Spool a finished round.
    fn push(&self, round: pb::Round) -> bool {
        let pushed = self.lock().push(round, rl_fed::now_ms());
        match pushed {
            Ok(_) => {
                self.ready.notify_one();
                true
            }
            Err(e) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                self.error(e.to_string());
                false
            }
        }
    }

    /// Log a spool error unless it is the same as the last one.
    fn error(&self, msg: String) {
        let mut last = self
            .last_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.as_deref() != Some(msg.as_str()) {
            eprintln!("routelith agent: spool: {msg}");
            *last = Some(msg);
        }
    }

    /// Log rounds dropped by the spool's bounds since the last report.
    fn report_drops(&self) {
        let now = self.lock().dropped();
        let mut reported = self.reported.lock().unwrap_or_else(PoisonError::into_inner);
        if now.rounds > reported.rounds {
            eprintln!(
                "routelith agent: spool full or too old: dropped {} round(s) the server had not stored",
                now.rounds - reported.rounds
            );
        }
        *reported = now;
    }
}

/// What this agent can measure, for Hello: ICMP only where it may send it.
fn capabilities() -> Vec<String> {
    let mut caps = Vec::new();
    if rl_probe::check_permission(false).is_ok() {
        caps.push("icmp4".to_string());
    }
    if rl_probe::check_permission(true).is_ok() {
        caps.push("icmp6".to_string());
    }
    caps.extend(["tcp", "dns", "http"].map(String::from));
    caps
}

/// How often the agent reports its spool.
const STATUS_EVERY: u32 = 30;

/// One connection: take the configuration, send spooled rounds, answer
/// clock probes, report status and health, until the stream ends.
/// Returns why it ended.
async fn session(
    mut s: client::Session,
    m: &mut Measuring,
    outbox: &Outbox,
    health: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> String {
    let mut sent = {
        let mut sp = outbox.lock();
        // The server may have stored more than we heard about (an Ack lost
        // with the connection).
        let stored = s.stored_seq;
        let r = if stored > sp.last_seq() {
            sp.skip_past(stored)
        } else {
            sp.ack(stored)
        };
        if let Err(e) = r {
            outbox.error(e.to_string());
        }
        if sp.backlog() > 0 {
            eprintln!("routelith agent: sending {} spooled round(s)", sp.backlog());
        }
        sp.acked()
    };
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut ticks = 0u32;
    loop {
        let mut due = false;
        let mut extra: Option<pb::agent_message::Msg> = None;
        tokio::select! {
            msg = s.inbound.message() => match msg {
                Ok(Some(pb::ServerMessage { msg: Some(pb::server_message::Msg::Clock(p)) })) => {
                    let t2 = rl_fed::now_us();
                    extra = Some(pb::agent_message::Msg::Clock(pb::ClockReply {
                        t1_us: p.t1_us,
                        t2_us: t2,
                        t3_us: rl_fed::now_us(),
                    }));
                }
                Ok(Some(pb::ServerMessage { msg: Some(pb::server_message::Msg::Config(snap)) })) => {
                    let applied = m.apply(snap).await;
                    let msg = pb::AgentMessage { msg: Some(pb::agent_message::Msg::Applied(applied)) };
                    if s.outbound.send(msg).await.is_err() {
                        return "the stream closed".to_string();
                    }
                }
                Ok(Some(pb::ServerMessage { msg: Some(pb::server_message::Msg::Ack(a)) })) => {
                    let r = outbox.lock().ack(a.up_to_seq);
                    if let Err(e) = r {
                        outbox.error(e.to_string());
                    }
                }
                Ok(Some(_)) => {}
                Ok(None) => return "the server closed the stream".to_string(),
                Err(st) => return st.message().to_string(),
            },
            () = outbox.ready.notified() => {}
            Some(json) = health.recv() => {
                extra = Some(pb::agent_message::Msg::Health(pb::Health { sample_json: json }));
            }
            _ = tick.tick() => {
                due = true;
                // The first tick comes at once: report the spool on connect.
                if ticks % STATUS_EVERY == 0 {
                    let sp = outbox.lock();
                    extra = Some(pb::agent_message::Msg::Status(pb::AgentStatus {
                        spool_bytes: sp.bytes(),
                        spool_backlog: sp.backlog(),
                    }));
                }
                ticks = ticks.wrapping_add(1);
                let r = outbox.lock().enforce(rl_fed::now_ms());
                if let Err(e) = r {
                    outbox.error(e.to_string());
                }
                outbox.report_drops();
            }
        }
        if let Some(msg) = extra {
            if s.outbound
                .send(pb::AgentMessage { msg: Some(msg) })
                .await
                .is_err()
            {
                return "the stream closed".to_string();
            }
        }
        // Send what is waiting: a full batch at once, the rest once a
        // second, never more than WINDOW unacknowledged.
        loop {
            let batch = {
                let mut sp = outbox.lock();
                let (acked, last) = (sp.acked(), sp.last_seq());
                sent = sent.max(acked);
                let pending = last - sent;
                if pending == 0 || sent - acked >= WINDOW || (pending < BATCH as u64 && !due) {
                    break;
                }
                let max = if pending > BATCH as u64 {
                    REPLAY_BATCH
                } else {
                    BATCH
                };
                match sp
                    .sync()
                    .and_then(|()| sp.read_after(sent, max, BATCH_BYTES))
                {
                    Ok(b) if b.is_empty() => {
                        // Dropped by the spool's bounds meanwhile.
                        sent = last;
                        break;
                    }
                    Ok(b) => b,
                    Err(e) => {
                        outbox.error(e.to_string());
                        break;
                    }
                }
            };
            sent = batch.last().map_or(sent, |r| r.seq);
            let msg = pb::AgentMessage {
                msg: Some(pb::agent_message::Msg::Results(pb::ResultBatch {
                    rounds: batch,
                })),
            };
            if s.outbound.send(msg).await.is_err() {
                return "the stream closed".to_string();
            }
        }
    }
}

/// A probe that measures only addresses in the allow-list: a round whose
/// host name resolves outside it fails without sending anything.
struct Guarded {
    inner: Arc<dyn Probe>,
    allow: Arc<AllowList>,
}

impl Probe for Guarded {
    fn kind(&self) -> rl_probe::ProbeKind {
        self.inner.kind()
    }

    fn run_round<'a>(
        &'a self,
        target: &'a rl_core::ResolvedTarget,
        plan: rl_core::RoundPlan,
    ) -> rl_probe::BoxFuture<'a, Result<rl_core::RoundResult, rl_probe::ProbeError>> {
        if self.allow.allows_addr(target.addr) {
            return self.inner.run_round(target, plan);
        }
        let msg = format!(
            "{} resolves to {}, which is not in this agent's allow list",
            target.name, target.addr
        );
        Box::pin(async move {
            Err(rl_probe::ProbeError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                msg,
            )))
        })
    }
}

/// The scheduler jobs for the current configuration.
struct Measuring {
    name: String,
    limiter: Arc<RateLimiter>,
    /// What this agent agrees to measure (§21.7 G6).
    allow: Arc<AllowList>,
    stats: Arc<Stats>,
    sink: Sink,
    version: Option<String>,
    stop: Option<tokio::sync::watch::Sender<bool>>,
    jobs: tokio::task::JoinSet<()>,
}

impl Measuring {
    fn new(name: &str, max_pps: u32, outbox: Arc<Outbox>) -> Self {
        let sink: Sink = Arc::new(move |c: Completed| {
            let round = match crate::server::stored(&c) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("routelith agent: series {}: invalid round: {e}", c.series);
                    return true;
                }
            };
            let http = crate::server::http_summary(&c).map(|(p, cert)| pb::HttpSummary {
                connect_us: p.connect,
                tls_us: p.tls,
                ttfb_us: p.ttfb,
                total_us: p.total,
                cert_not_after_s: cert,
            });
            // The spool gives it its seq.
            outbox.push(rl_fed::assign::to_wire(0, c.series, &round, http))
        });
        Measuring {
            name: name.to_string(),
            limiter: Arc::new(RateLimiter::new(max_pps)),
            allow: Arc::default(),
            stats: Arc::new(Stats::default()),
            sink,
            version: None,
            stop: None,
            jobs: tokio::task::JoinSet::new(),
        }
    }

    async fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(true);
        }
        while self.jobs.join_next().await.is_some() {}
        self.version = None;
    }

    /// Measure what `snap` says. The same version again (after a
    /// reconnect) keeps the running jobs.
    async fn apply(&mut self, snap: pb::ConfigSnapshot) -> pb::ConfigApplied {
        let mut refused = Vec::new();
        if self.version.as_deref() == Some(snap.version.as_str()) {
            return pb::ConfigApplied {
                version: snap.version,
                refused,
            };
        }
        self.stop().await;
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let mut probes: HashMap<ProbeConfig, Arc<dyn Probe>> = HashMap::new();
        let mut icmp_ok: [Option<Result<(), String>>; 2] = [None, None];
        let mut started = 0usize;
        for a in &snap.assignments {
            let spec = match rl_fed::assign::spec(a) {
                Ok(s) => s,
                Err(e) => {
                    refused.push(refusal(a.series_id, e.to_string()));
                    continue;
                }
            };
            let each_round = match self.allow.check(&spec.host, &spec.probe) {
                Verdict::Allowed => false,
                Verdict::EachRound => true,
                Verdict::Refused(why) => {
                    refused.push(refusal(a.series_id, why));
                    continue;
                }
            };
            let mut v6_usable = true;
            if matches!(spec.probe, ProbeConfig::Icmp { .. }) {
                let mut allowed = |v6: bool| {
                    icmp_ok[usize::from(v6)]
                        .get_or_insert_with(|| {
                            rl_probe::check_permission(v6).map_err(|e| e.to_string())
                        })
                        .clone()
                };
                let check = match spec.family {
                    Family::V4 => allowed(false),
                    Family::V6 => allowed(true),
                    _ => {
                        v6_usable = allowed(true).is_ok();
                        if v6_usable { Ok(()) } else { allowed(false) }
                    }
                };
                if let Err(e) = check {
                    refused.push(refusal(a.series_id, format!("cannot send ICMP: {e}")));
                    continue;
                }
            }
            let probe = match probes.get(&spec.probe) {
                Some(p) => p.clone(),
                None => match crate::server::make_probe(&spec.probe, &self.limiter) {
                    Ok(p) => probes.entry(spec.probe.clone()).or_insert(p).clone(),
                    Err(e) => {
                        refused.push(refusal(a.series_id, e.to_string()));
                        continue;
                    }
                },
            };
            // A host name passes a network entry only with the address
            // each round resolves to.
            let probe: Arc<dyn Probe> = if each_round {
                Arc::new(Guarded {
                    inner: probe,
                    allow: self.allow.clone(),
                })
            } else {
                probe
            };
            let job = Job {
                series: a.series_id,
                vantage: self.name.clone(),
                target: a.target.clone(),
                host: spec.host,
                family: spec.family,
                v6_usable,
                schedule: spec.schedule,
            };
            self.jobs.spawn(rl_sched::run_job(
                job,
                probe,
                self.sink.clone(),
                self.stats.clone(),
                stop_rx.clone(),
            ));
            started += 1;
        }
        eprintln!(
            "routelith agent: configuration {}: measuring {started} series{}",
            snap.version,
            if refused.is_empty() {
                String::new()
            } else {
                format!(", {} refused", refused.len())
            }
        );
        for r in &refused {
            eprintln!(
                "routelith agent: series {} refused: {}",
                r.series_id, r.reason
            );
        }
        self.stop = Some(stop_tx);
        self.version = Some(snap.version.clone());
        pb::ConfigApplied {
            version: snap.version,
            refused,
        }
    }
}

fn refusal(series_id: u64, reason: String) -> pb::Refusal {
    pb::Refusal { series_id, reason }
}

/// Reconnect delays: 1, 2, 4 … 60 s; back to 1 s after a connection that
/// lasted a minute.
#[derive(Debug, Default)]
struct Backoff {
    next: Duration,
}

impl Backoff {
    fn next(&mut self, lasted: Duration) -> Duration {
        if lasted >= Duration::from_secs(60) || self.next.is_zero() {
            self.next = Duration::from_secs(1);
        }
        let now = self.next;
        self.next = (self.next * 2).min(Duration::from_secs(60));
        now
    }
}

#[derive(Debug, Args)]
pub(crate) struct CtlAgentArgs {
    #[command(subcommand)]
    action: CtlAgentAction,
    /// The server's configuration file (for its data_dir and vantage).
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum CtlAgentAction {
    /// Make a single-use enrollment token for a new agent (or to enroll an
    /// existing one again, which replaces its certificate).
    Add {
        name: String,
        /// How long the token stays valid, e.g. 24h or 30m.
        #[arg(long, default_value = "24h")]
        valid: String,
    },
    /// List enrolled agents and unused tokens.
    List,
    /// Revoke an agent: its certificate is refused from now on.
    Revoke { name: String },
}

type Failed = (u8, String);

pub(crate) fn ctl(args: CtlAgentArgs) -> ExitCode {
    match ctl_inner(args) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err((code, msg)) => {
            eprintln!("routelith ctl agent: {msg}");
            ExitCode::from(code)
        }
    }
}

fn ctl_inner(args: CtlAgentArgs) -> Result<String, Failed> {
    let path = args
        .config
        .ok_or((2, "need --config (the server's)".to_string()))?;
    let src =
        std::fs::read_to_string(&path).map_err(|e| (2, format!("{}: {e}", path.display())))?;
    let cfg = config::parse(&src).config.ok_or_else(|| {
        (
            2,
            format!(
                "{} is invalid; check it with `routelith ctl verify`",
                path.display()
            ),
        )
    })?;
    let data_dir = &cfg.server.data_dir;
    let registry = Registry::new(data_dir);
    let fed = |e: rl_fed::FedError| (2u8, e.to_string());
    let now = rl_fed::now_ms();
    match args.action {
        CtlAgentAction::Add { name, valid } => {
            rl_fed::registry::check_name(&name).map_err(|e| (1, e.to_string()))?;
            if name == cfg.server.vantage {
                return Err((1, format!("{name:?} is the server's own vantage name")));
            }
            let ttl = rl_core::duration::parse(&valid)
                .ok()
                .and_then(|d| i64::try_from(d.as_millis()).ok())
                .filter(|ms| (60_000..=30 * TOKEN_TTL_MS).contains(ms))
                .ok_or((1, format!("--valid {valid:?}: give 1m to 720h")))?;
            let ca = Ca::load_or_create(data_dir).map_err(fed)?;
            let again = registry.get(&name).map_err(fed)?.is_some();
            let secret = registry.add_token(&name, ttl, now).map_err(|e| match e {
                rl_fed::FedError::Invalid(m) => (1, m),
                e => (2, e.to_string()),
            })?;
            let token = Token {
                secret,
                ca_sha256: ca.fingerprint(),
            };
            let mut msg = format!(
                "Enrollment token for agent {name}, valid for {valid}, works once:\n\n{}\n\n\
                 On the agent: routelith agent enroll --config agent.toml --token <token>",
                token.encode()
            );
            if again {
                msg.push_str(&format!(
                    "\n\nAgent {name} is already enrolled: enrolling again replaces its certificate."
                ));
            }
            if cfg.server.listen_agents.is_none() {
                msg.push_str(
                    "\n\nNote: listen_agents is not set in this configuration, so the server \
                     does not accept agents yet.",
                );
            }
            Ok(msg)
        }
        CtlAgentAction::List => {
            let agents = registry.list().map_err(fed)?;
            let tokens = registry.pending_tokens(now).map_err(fed)?;
            if agents.is_empty() && tokens.is_empty() {
                return Ok("no agents enrolled and no tokens waiting".to_string());
            }
            let mut out = String::new();
            for a in &agents {
                let state = match a.revoked_ms {
                    Some(t) => format!("revoked {}", when(t)),
                    None => format!("certificate valid until {}", when(a.cert_expires_ms)),
                };
                out.push_str(&format!(
                    "{}  enrolled {}, version {}, {state}\n",
                    a.name,
                    when(a.enrolled_ms),
                    a.version
                ));
            }
            for t in &tokens {
                out.push_str(&format!(
                    "{}  token waiting, valid until {}\n",
                    t.name,
                    when(t.expires_ms)
                ));
            }
            Ok(out.trim_end().to_string())
        }
        CtlAgentAction::Revoke { name } => {
            rl_fed::registry::check_name(&name).map_err(|e| (1, e.to_string()))?;
            if registry.revoke(&name, now).map_err(fed)? {
                Ok(format!(
                    "agent {name} revoked; a running server drops its stream within 10 s"
                ))
            } else {
                Err((1, format!("no agent named {name}")))
            }
        }
    }
}

/// UTC time stamp for listings.
fn when(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_a_minute_and_resets() {
        let mut b = Backoff::default();
        let z = Duration::ZERO;
        let got: Vec<u64> = (0..8).map(|_| b.next(z).as_secs()).collect();
        assert_eq!(got, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(b.next(Duration::from_secs(61)).as_secs(), 1);
    }

    #[test]
    fn times_print_in_utc() {
        assert_eq!(when(0), "1970-01-01 00:00 UTC");
        assert_eq!(when(1_795_615_932_609), "2026-11-25 14:12 UTC");
    }
}
