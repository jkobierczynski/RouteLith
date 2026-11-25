//! Agents (§21.7): `routelith agent enroll|run` on the agent, and
//! `routelith ctl agent add|list|revoke` on the server.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use rl_core::config;
use rl_fed::agent_config::AgentConfig;
use rl_fed::ca::Ca;
use rl_fed::client::{self, Identity};
use rl_fed::registry::{Registry, TOKEN_TTL_MS};
use rl_fed::token::Token;

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
    /// Connect to the server and stay connected, reconnecting after
    /// failures. (Measuring for the server arrives with M3 step 2.)
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
    eprintln!("routelith agent: {} connecting to {}", id.name, cfg.server);
    tokio::pin!(signal);
    let mut backoff = Backoff::default();
    loop {
        let attempt = async {
            let started = Instant::now();
            match client::connect(&cfg.server, &id, VERSION).await {
                Ok(mut s) => {
                    eprintln!(
                        "routelith agent: connected to {} as {} (server version {})",
                        cfg.server, s.name, s.server_version
                    );
                    let why = loop {
                        match s.inbound.message().await {
                            Ok(Some(_)) => {}
                            Ok(None) => break "the server closed the stream".to_string(),
                            Err(st) => break st.message().to_string(),
                        }
                    };
                    eprintln!("routelith agent: disconnected: {why}");
                    started.elapsed()
                }
                Err(e) => {
                    eprintln!("routelith agent: {e}");
                    Duration::ZERO
                }
            }
        };
        tokio::select! {
            () = &mut signal => break,
            lasted = attempt => {
                let wait = backoff.next(lasted);
                eprintln!("routelith agent: trying again in {} s", wait.as_secs());
                tokio::select! {
                    () = &mut signal => break,
                    () = tokio::time::sleep(wait) => {}
                }
            }
        }
    }
    eprintln!("routelith agent: stopping");
    ExitCode::SUCCESS
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
