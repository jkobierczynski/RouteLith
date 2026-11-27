//! `routelith trace`: trace the path to a host from this machine
//! (architecture doc §8.2, §21.9 P15). No server or configuration needed,
//! and no root or Administrator.
//!
//! For now this prints a report after `--count` sweeps (as `mtr --report`);
//! the live view arrives with the trace TUI.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Args;
use rl_path::{HopStats, Session, SweepPlan, TraceStats};
use serde::Serialize;

use crate::check::{parse_duration, resolve};

const MIN_INTERVAL: Duration = Duration::from_millis(100);
const MAX_INTERVAL: Duration = Duration::from_secs(60);
const MAX_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Args)]
pub(crate) struct TraceArgs {
    /// Host name or IP address to trace.
    host: String,
    /// Print a report after the sweeps and exit (the only mode until the
    /// live view arrives).
    #[arg(long)]
    report: bool,
    /// Sweeps to run.
    #[arg(short = 'c', long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..))]
    count: u32,
    /// Time between sweeps; each sweep's probes are spread over it.
    #[arg(short, long, default_value = "1s", value_parser = parse_duration)]
    interval: Duration,
    /// Highest TTL to probe.
    #[arg(short = 'm', long, default_value_t = 30, value_parser = clap::value_parser!(u8).range(1..=64))]
    max_ttl: u8,
    /// How long each probe waits for an answer.
    #[arg(short = 'W', long, default_value = "2s", value_parser = parse_duration)]
    timeout: Duration,
    /// Use IPv4 only.
    #[arg(short = '4', conflicts_with = "ipv6")]
    ipv4: bool,
    /// Use IPv6 only.
    #[arg(short = '6')]
    ipv6: bool,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct JsonReport<'a> {
    host: &'a str,
    dest: IpAddr,
    sweeps: u64,
    interval_ms: u128,
    timing: &'static str,
    reached: bool,
    hops: Vec<HopStats>,
}

pub(crate) async fn run(args: TraceArgs) -> ExitCode {
    if args.interval < MIN_INTERVAL
        || args.interval > MAX_INTERVAL
        || args.timeout.is_zero()
        || args.timeout > MAX_TIMEOUT
    {
        eprintln!(
            "routelith trace: interval must be 100ms to 60s and timeout more than 0 and at most 10s"
        );
        return ExitCode::from(2);
    }
    let dest = match resolve(&args.host, args.ipv4, args.ipv6).await {
        Ok(addr) => addr,
        Err(msg) => {
            eprintln!("routelith trace: {msg}");
            return ExitCode::from(2);
        }
    };
    let tracer = match rl_path::open(dest) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("routelith trace: {e}");
            return ExitCode::from(2);
        }
    };
    if !args.report && !args.json {
        eprintln!("routelith trace: the live view is not available yet; showing a report");
    }
    let plan = SweepPlan {
        interval: args.interval,
        max_ttl: args.max_ttl,
        timeout: args.timeout,
    };
    let mut session = Session::new(plan);
    let mut stats = TraceStats::new();
    let mut timing = tracer.timing();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut tick = tokio::time::interval(args.interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut started = 0u32;
    let mut done = 0u32;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    while done < args.count {
        tokio::select! {
            _ = tick.tick(), if started < args.count => {
                started += 1;
                let (tracer, tx, n) = (Arc::clone(&tracer), tx.clone(), session.next_count());
                tokio::spawn(async move {
                    let _ = tx.send(rl_path::run_sweep(tracer, n, plan).await);
                });
            }
            Some(sweep) = rx.recv() => {
                done += 1;
                session.record(&sweep);
                stats.add(&sweep);
                if sweep.timing != tracer.timing() {
                    timing = sweep.timing;
                }
            }
            _ = &mut ctrl_c => break,
        }
    }
    let hops = stats.hops();
    let reached = hops.last().is_some_and(|h| h.is_dest);
    if args.json {
        let report = JsonReport {
            host: &args.host,
            dest,
            sweeps: stats.sweeps(),
            interval_ms: args.interval.as_millis(),
            timing: timing.describe(),
            reached,
            hops,
        };
        match serde_json::to_string_pretty(&report) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("routelith trace: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        print!(
            "{}",
            render(
                &args.host,
                dest,
                stats.sweeps(),
                args.interval,
                timing.describe(),
                &hops
            )
        );
    }
    if reached {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn ms(us: Option<u64>) -> String {
    us.map_or_else(|| "-".into(), |us| format!("{:.2}", us as f64 / 1000.0))
}

fn msf(us: Option<f64>) -> String {
    us.map_or_else(|| "-".into(), |us| format!("{:.2}", us / 1000.0))
}

/// The report table. Its layout is stable: the lab script parses it.
fn render(
    host: &str,
    dest: IpAddr,
    sweeps: u64,
    interval: Duration,
    timing: &str,
    hops: &[HopStats],
) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "routelith trace to {host} ({dest}), {sweeps} sweeps every {}, timing: {timing}",
        rl_core::duration::format(interval)
    );
    let _ = writeln!(
        out,
        "{:>3}  {:<39} {:>6} {:>5} {:>5} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "Hop", "Host", "Loss%", "Sent", "Recv", "Last", "Min", "Avg", "Median", "Max", "StDev"
    );
    for h in hops {
        let host = match h.responders.first() {
            Some(r) => r.addr.to_string(),
            None => "???".into(),
        };
        let _ = writeln!(
            out,
            "{:>3}  {:<39} {:>6.1} {:>5} {:>5} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}",
            h.ttl,
            host,
            h.loss_pct(),
            h.sent,
            h.received,
            ms(h.last_us),
            ms(h.min_us),
            msf(h.mean_us),
            ms(h.median_us),
            ms(h.max_us),
            msf(h.stddev_us),
        );
        // Further responders at this TTL (ECMP), with their share.
        if h.responders.len() > 1 {
            for r in &h.responders {
                let share = 100.0 * r.replies as f64 / h.received.max(1) as f64;
                let _ = writeln!(
                    out,
                    "{:>3}  {:<39} {share:>5.1}% of replies",
                    "",
                    format!("  {}", r.addr)
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rl_path::Responder;

    use super::*;

    #[test]
    fn report_format_is_stable() {
        let ip = |n| IpAddr::V4(Ipv4Addr::new(192, 0, 2, n));
        let hops = vec![
            HopStats {
                ttl: 1,
                sent: 10,
                received: 10,
                responders: vec![Responder {
                    addr: ip(1),
                    replies: 10,
                }],
                last_us: Some(1100),
                min_us: Some(1000),
                max_us: Some(1500),
                mean_us: Some(1200.0),
                median_us: Some(1150),
                stddev_us: Some(100.0),
                ..HopStats::default()
            },
            HopStats {
                ttl: 2,
                sent: 10,
                ..HopStats::default()
            },
            HopStats {
                ttl: 3,
                sent: 10,
                received: 8,
                responders: vec![
                    Responder {
                        addr: ip(7),
                        replies: 6,
                    },
                    Responder {
                        addr: ip(8),
                        replies: 2,
                    },
                ],
                is_dest: true,
                last_us: Some(3000),
                min_us: Some(3000),
                max_us: Some(3000),
                mean_us: Some(3000.0),
                median_us: Some(3000),
                stddev_us: Some(0.0),
                ..HopStats::default()
            },
        ];
        let out = render(
            "example",
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            10,
            Duration::from_secs(1),
            "kernel timestamps (ping socket)",
            &hops,
        );
        let expected = "\
routelith trace to example (198.51.100.10), 10 sweeps every 1s, timing: kernel timestamps (ping socket)
Hop  Host                                     Loss%  Sent  Recv     Last      Min      Avg   Median      Max    StDev
  1  192.0.2.1                                  0.0    10    10     1.10     1.00     1.20     1.15     1.50     0.10
  2  ???                                      100.0    10     0        -        -        -        -        -        -
  3  192.0.2.7                                 20.0    10     8     3.00     3.00     3.00     3.00     3.00     0.00
       192.0.2.7                              75.0% of replies
       192.0.2.8                              25.0% of replies
";
        assert_eq!(out, expected);
    }
}
