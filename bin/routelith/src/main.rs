//! The `routelith` binary: one executable, several modes (architecture doc §3).
//!
//! Only the M0 subcommands exist so far, and none of them is implemented yet.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    /// ICMP echo round.
    Icmp(IcmpArgs),
}

#[derive(Debug, Args)]
struct IcmpArgs {
    /// Host name or IP address to measure.
    host: String,
    /// Number of samples in the round.
    #[arg(short = 'c', long, default_value_t = 20)]
    count: u16,
}

#[derive(Debug, Subcommand)]
enum CtlAction {
    /// Validate a configuration file without starting anything.
    Verify {
        /// Path to the TOML configuration file.
        config: PathBuf,
    },
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
        Command::Server { .. } => "server",
        Command::Check { .. } => "check",
        Command::Ctl {
            action: CtlAction::Verify { .. },
        } => "ctl verify",
        Command::Ctl {
            action: CtlAction::Render { .. },
        } => "ctl render",
    };
    eprintln!("routelith {name}: not implemented yet (planned for M0)");
    ExitCode::from(2)
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
