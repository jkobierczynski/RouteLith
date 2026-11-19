//! The `routelith` binary: one executable, several modes (architecture doc §3).
//!
//! `server`, `check icmp|tcp|dns|http`,
//! `ctl calibrate`, `ctl verify` and `ctl render` work.
#![forbid(unsafe_code)]

mod calibrate;
mod check;
mod health;
mod render;
mod server;
mod verify;

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "routelith", version, about, propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the scheduler and store in the foreground (M0: no UI or API yet).
    Server(server::ServerArgs),
    /// One-shot measurement for debugging and scripting.
    Check {
        #[command(subcommand)]
        probe: CheckProbe,
    },
    /// Administration: verify configuration, render graphs.
    Ctl {
        #[command(subcommand)]
        action: CtlAction,
    },
}

#[derive(Debug, Subcommand)]
enum CheckProbe {
    /// ICMP echo round (unprivileged: Linux ping socket, Windows ICMP API).
    Icmp(check::IcmpArgs),
    /// TCP connect time (or time to the server's banner).
    Tcp(check::TcpArgs),
    /// DNS query time to a server, bypassing local caches.
    Dns(check::DnsArgs),
    /// HTTP(S) request timing: connect, TLS, time to first byte, total.
    Http(check::HttpArgs),
}

#[derive(Debug, Subcommand)]
enum CtlAction {
    /// Validate a configuration file without starting anything.
    Verify(verify::VerifyArgs),
    /// Measure the Windows ICMP API timing error against a raw-socket
    /// reference (Windows only, needs Administrator).
    Calibrate(calibrate::CalibrateArgs),
    /// Render a smoke graph from the store as SVG.
    Render(render::RenderArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Check {
            probe: CheckProbe::Icmp(args),
        } => run(check::icmp(args)),
        Command::Check {
            probe: CheckProbe::Tcp(args),
        } => run(check::tcp(args)),
        Command::Check {
            probe: CheckProbe::Dns(args),
        } => run(check::dns(args)),
        Command::Check {
            probe: CheckProbe::Http(args),
        } => run(check::http(args)),
        Command::Ctl {
            action: CtlAction::Calibrate(args),
        } => calibrate::run(&args),
        Command::Ctl {
            action: CtlAction::Verify(args),
        } => run(verify::run(args)),
        Command::Server(args) => run(server::run(args)),
        Command::Ctl {
            action: CtlAction::Render(args),
        } => render::run(&args),
    }
}

fn run(fut: impl std::future::Future<Output = ExitCode>) -> ExitCode {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => {
            let code = rt.block_on(fut);
            // Don't wait for blocking work left behind, such as a system DNS
            // lookup that outlived its timeout: the result is already out.
            rt.shutdown_timeout(Duration::from_millis(100));
            code
        }
        Err(e) => {
            eprintln!("routelith: cannot start async runtime: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
