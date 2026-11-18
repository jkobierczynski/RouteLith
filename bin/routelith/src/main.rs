//! The `routelith` binary: one executable, several modes (architecture doc §3).
//!
//! Only the M0 subcommands exist so far; `check icmp`, `ctl calibrate` and
//! `ctl verify` work, the rest are stubs.
#![forbid(unsafe_code)]

mod calibrate;
mod check;
mod verify;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "routelith", version, about, propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the scheduler and store in the foreground (M0: no UI or API yet).
    Server {
        /// Path to the TOML configuration file.
        #[arg(short, long)]
        config: PathBuf,
    },
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
}

#[derive(Debug, Subcommand)]
enum CtlAction {
    /// Validate a configuration file without starting anything.
    Verify(verify::VerifyArgs),
    /// Measure the Windows ICMP API timing error against a raw-socket
    /// reference (Windows only, needs Administrator).
    Calibrate(calibrate::CalibrateArgs),
    /// Render a smoke graph from the store as SVG.
    Render {
        /// Target id as configured.
        #[arg(long)]
        target: String,
        /// Time range to draw.
        #[arg(long, value_enum, default_value_t = Range::H3)]
        range: Range,
        /// Output SVG file.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Range {
    #[value(name = "3h")]
    H3,
    #[value(name = "30h")]
    H30,
    #[value(name = "10d")]
    D10,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let name = match cli.command {
        Command::Check {
            probe: CheckProbe::Icmp(args),
        } => return run(check::icmp(args)),
        Command::Ctl {
            action: CtlAction::Calibrate(args),
        } => return calibrate::run(&args),
        Command::Ctl {
            action: CtlAction::Verify(args),
        } => return run(verify::run(args)),
        Command::Server { .. } => "server",
        Command::Ctl {
            action: CtlAction::Render { .. },
        } => "ctl render",
    };
    eprintln!("routelith {name}: not implemented yet (planned for M0)");
    ExitCode::from(2)
}

fn run(fut: impl std::future::Future<Output = ExitCode>) -> ExitCode {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt.block_on(fut),
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
