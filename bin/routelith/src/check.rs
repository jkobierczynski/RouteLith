//! `routelith check`: one-shot measurement for debugging and scripting.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use clap::Args;
use rl_core::{ResolvedTarget, RoundPlan, RoundResult, RoundStats, Sample};
use rl_probe::{IcmpConfig, IcmpProbe, Probe};

#[derive(Debug, Args)]
pub(crate) struct IcmpArgs {
    /// Host name or IP address to measure.
    host: String,
    /// Number of samples in the round.
    #[arg(short = 'c', long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..))]
    count: u16,
    /// Time between samples, e.g. 1s, 200ms.
    #[arg(short = 'i', long, default_value = "1s", value_parser = parse_duration)]
    interval: Duration,
    /// Per-sample timeout, e.g. 2s.
    #[arg(short = 'W', long, default_value = "2s", value_parser = parse_duration)]
    timeout: Duration,
    /// ICMP payload size in bytes (minimum 8).
    #[arg(short = 's', long, default_value_t = 56)]
    size: u16,
    /// Use IPv4 only.
    #[arg(short = '4', conflicts_with = "ipv6")]
    ipv4: bool,
    /// Use IPv6 only.
    #[arg(short = '6')]
    ipv6: bool,
    /// Print only the summary.
    #[arg(short, long)]
    quiet: bool,
}

pub(crate) async fn icmp(args: IcmpArgs) -> ExitCode {
    let addr = match resolve(&args.host, args.ipv4, args.ipv6).await {
        Ok(addr) => addr,
        Err(msg) => {
            eprintln!("routelith check: {msg}");
            return ExitCode::from(2);
        }
    };
    let target = ResolvedTarget {
        name: args.host.clone(),
        addr,
    };
    let plan = RoundPlan {
        count: args.count,
        spread: args.interval * u32::from(args.count),
        timeout: args.timeout,
        round_start: SystemTime::now(),
    };
    let probe = IcmpProbe::new(IcmpConfig {
        payload_size: args.size,
    });
    match probe.run_round(&target, plan).await {
        Ok(round) => {
            print!("{}", render(&target, &round, args.quiet));
            let stats = RoundStats::from_samples(&round.samples);
            if stats.received == 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("routelith check: {e}");
            ExitCode::from(2)
        }
    }
}

async fn resolve(host: &str, v4_only: bool, v6_only: bool) -> Result<IpAddr, String> {
    let wanted = |a: &IpAddr| (!v4_only || a.is_ipv4()) && (!v6_only || a.is_ipv6());
    if let Ok(addr) = host.parse::<IpAddr>() {
        return if wanted(&addr) {
            Ok(addr)
        } else {
            Err(format!("{host} is not of the requested address family"))
        };
    }
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .map(|sa| sa.ip())
        .filter(wanted)
        .collect();
    // Like ping: prefer IPv4 unless -6 was given.
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| format!("{host} has no address of the requested family"))
}

fn ms(us: u32) -> String {
    format!("{:.3}", f64::from(us) / 1000.0)
}

/// Render a round as text. The summary lines are stable and parsed by the
/// accuracy lab script (`tests/lab/netem-accuracy.sh`).
fn render(target: &ResolvedTarget, round: &RoundResult, quiet: bool) -> String {
    let mut out = String::new();
    let stats = RoundStats::from_samples(&round.samples);
    let _ = writeln!(
        out,
        "ICMP {} ({}): {} samples, {}-byte payload",
        target.name,
        round.meta.resolved,
        round.samples.len(),
        round.meta.payload_size
    );
    if !quiet {
        for (i, sample) in round.samples.iter().enumerate() {
            let line = match sample {
                Sample::Ok { rtt_us } => format!("{} ms", ms(*rtt_us)),
                Sample::Lost => "lost".to_owned(),
                Sample::Error(e) => format!("error: {e}"),
            };
            let _ = writeln!(out, "  #{:<4} {line}", i + 1);
        }
    }
    let _ = writeln!(
        out,
        "--- {} sent, {} received, {:.1}% loss",
        stats.sent,
        stats.received,
        stats.loss_ratio() * 100.0
    );
    if let (Some(min), Some(med), Some(p90), Some(max)) =
        (stats.min_us, stats.median_us, stats.p90_us, stats.max_us)
    {
        let _ = writeln!(
            out,
            "rtt min/median/p90/max = {}/{}/{}/{} ms",
            ms(min),
            ms(med),
            ms(p90),
            ms(max)
        );
    }
    let _ = writeln!(out, "timing: {}", round.meta.timing);
    out
}

/// Parse `1s`, `250ms`, `500us` or a bare number of seconds.
fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let (num, unit) = match s.find(|c: char| c.is_ascii_alphabetic()) {
        Some(i) => s.split_at(i),
        None => (s, "s"),
    };
    let value: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration: {s}"))?;
    let secs = match unit {
        "s" => value,
        "ms" => value / 1e3,
        "us" | "µs" => value / 1e6,
        _ => return Err(format!("unknown unit in {s} (use s, ms or us)")),
    };
    Duration::try_from_secs_f64(secs).map_err(|_| format!("invalid duration: {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_core::{ProbeMeta, TimingBackend, TimingSource};

    #[test]
    fn durations() {
        assert_eq!(parse_duration("1s"), Ok(Duration::from_secs(1)));
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("500us"), Ok(Duration::from_micros(500)));
        assert_eq!(parse_duration("2"), Ok(Duration::from_secs(2)));
        assert!(parse_duration("5m").is_err());
        assert!(parse_duration("-1s").is_err());
    }

    #[test]
    fn summary_format_is_stable() {
        let target = ResolvedTarget {
            name: "lab".into(),
            addr: "192.0.2.1".parse().unwrap(),
        };
        let round = RoundResult {
            start: SystemTime::UNIX_EPOCH,
            samples: vec![
                Sample::Ok { rtt_us: 10_100 },
                Sample::Lost,
                Sample::Ok { rtt_us: 10_300 },
            ],
            meta: ProbeMeta {
                resolved: target.addr,
                timing: TimingSource::new(TimingBackend::LinuxKernelTimestamp),
                payload_size: 56,
            },
        };
        let text = render(&target, &round, true);
        assert_eq!(
            text,
            "ICMP lab (192.0.2.1): 3 samples, 56-byte payload\n\
             --- 3 sent, 2 received, 33.3% loss\n\
             rtt min/median/p90/max = 10.100/10.200/10.300/10.300 ms\n\
             timing: kernel timestamps (ping socket), precision ±0.05 ms\n"
        );
    }
}
