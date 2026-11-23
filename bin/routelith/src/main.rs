//! The `routelith` binary: one executable, several modes (architecture doc §3).
//!
//! `server`, `service install|uninstall`, `check icmp|tcp|dns|http`,
//! `ctl calibrate`, `ctl verify`, `ctl render` and `ctl import smokeping`
//! work.
#![forbid(unsafe_code)]

mod alerting;
mod calibrate;
mod check;
mod health;
mod import;
mod render;
mod server;
mod service;
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
    /// Run the scheduler, store, web UI and API in the foreground.
    Server(server::ServerArgs),
    /// One-shot measurement for debugging and scripting.
    Check {
        #[command(subcommand)]
        probe: CheckProbe,
    },
    /// Install, remove or run the server as a Windows Service.
    Service {
        #[command(subcommand)]
        action: service::ServiceAction,
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
    /// Import history from another tool into the store (with the server
    /// stopped).
    Import {
        #[command(subcommand)]
        from: ImportFrom,
    },
}

#[derive(Debug, Subcommand)]
enum ImportFrom {
    /// A SmokePing target's RRD, as `rrdtool dump` XML.
    Smokeping(import::SmokepingArgs),
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
        Command::Service { action } => service::run(action),
        Command::Ctl {
            action: CtlAction::Render(args),
        } => render::run(&args),
        Command::Ctl {
            action:
                CtlAction::Import {
                    from: ImportFrom::Smokeping(args),
                },
        } => import::run(&args),
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

    mod messages {
        include!("../build/messages.rs");

        fn u32_at(b: &[u8], i: usize) -> u32 {
            u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
        }

        /// The table reads back as Windows reads it: each block's IDs map to
        /// an entry whose text is "%1".
        #[test]
        fn the_message_table_reads_back() {
            let b = message_table();
            assert_eq!(u32_at(&b, 0), 3);
            let mut ids = 0;
            for blk in 0..3 {
                let (low, high, off) = (
                    u32_at(&b, 4 + 12 * blk),
                    u32_at(&b, 8 + 12 * blk),
                    u32_at(&b, 12 + 12 * blk) as usize,
                );
                let mut at = off;
                for _ in low..=high {
                    let len = usize::from(u16::from_le_bytes([b[at], b[at + 1]]));
                    assert_eq!(len % 4, 0);
                    assert_eq!(u16::from_le_bytes([b[at + 2], b[at + 3]]), 1);
                    let text: Vec<u16> = b[at + 4..at + len]
                        .chunks(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&c| c != 0)
                        .collect();
                    assert_eq!(String::from_utf16(&text).unwrap(), "%1\r\n");
                    at += len;
                    ids += 1;
                }
                if blk == 2 {
                    assert_eq!(at, b.len());
                }
            }
            assert_eq!(ids, 300);
            assert!(RANGES.iter().any(|&(l, h)| (l..=h).contains(&1000)));
            assert!(RANGES.iter().any(|&(l, h)| (l..=h).contains(&3001)));
        }
    }
}
