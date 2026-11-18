//! `routelith check`: one-shot measurement for debugging and scripting.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use clap::Args;
use rl_core::{ResolvedTarget, RoundPlan, RoundResult, RoundStats, Sample, SampleError};
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

const MAX_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_TIMEOUT: Duration = Duration::from_secs(60);

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
    // Bounds that keep every offset and deadline of the round representable
    // (and match the configuration's limits).
    if args.interval > MAX_INTERVAL || args.timeout > MAX_TIMEOUT {
        eprintln!(
            "routelith check: interval must be at most {} and timeout at most {}",
            rl_core::duration::format(MAX_INTERVAL),
            rl_core::duration::format(MAX_TIMEOUT)
        );
        return ExitCode::from(2);
    }
    let spread = args.interval * u32::from(args.count);
    let plan = RoundPlan {
        count: args.count,
        spread,
        timeout: args.timeout,
        round_start: SystemTime::now(),
    };
    let probe = IcmpProbe::new(IcmpConfig {
        payload_size: args.size,
    });
    match probe.run_round(&target, plan).await {
        Ok(round) => {
            print!("{}", render(&target, &round, args.quiet));
            exit_code(&round.samples)
        }
        Err(e) => {
            eprintln!("routelith check: {e}");
            ExitCode::from(2)
        }
    }
}

/// 0 if any reply arrived; 2 if nothing came back and at least one request
/// failed locally (it never left this host); 1 for plain 100 % loss.
fn exit_code(samples: &[Sample]) -> ExitCode {
    let stats = RoundStats::from_samples(samples);
    let local_failure = samples
        .iter()
        .any(|s| matches!(s, Sample::Error(SampleError::SendFailed(_))));
    if stats.received > 0 {
        ExitCode::SUCCESS
    } else if local_failure {
        ExitCode::from(2)
    } else {
        ExitCode::from(1)
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
pub(crate) fn parse_duration(s: &str) -> Result<Duration, String> {
    rl_core::duration::parse(s)
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
        assert_eq!(parse_duration("500µs"), Ok(Duration::from_micros(500)));
        assert_eq!(parse_duration("2"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert!(parse_duration("-1s").is_err());
    }

    #[test]
    fn exit_codes() {
        let ok = Sample::Ok { rtt_us: 1 };
        let local = Sample::Error(SampleError::SendFailed("ENETUNREACH".into()));
        let remote = Sample::Error(SampleError::Unreachable { code: 1 });
        assert_eq!(exit_code(&[ok.clone(), local.clone()]), ExitCode::SUCCESS);
        assert_eq!(exit_code(&[Sample::Lost, local]), ExitCode::from(2));
        assert_eq!(exit_code(&[Sample::Lost, remote]), ExitCode::from(1));
        assert_eq!(exit_code(&[Sample::Lost]), ExitCode::from(1));
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
