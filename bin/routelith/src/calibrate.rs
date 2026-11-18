//! `routelith ctl calibrate`: measure the Windows ICMP API timing error against
//! a raw-socket reference (architecture doc, risk R1). Windows only; needs
//! Administrator for the raw socket.

use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use rl_probe::calibration::{Dist, Summary};

use crate::check::parse_duration;

#[derive(Debug, Args)]
pub(crate) struct CalibrateArgs {
    /// IPv4 address to echo (default: loopback, which isolates the API overhead).
    #[arg(long, default_value = "127.0.0.1")]
    target: Ipv4Addr,
    /// Number of pairs (one API echo plus one raw-socket echo each).
    #[arg(short = 'c', long, default_value_t = 1000, value_parser = clap::value_parser!(u16).range(1..))]
    count: u16,
    /// Time between pairs, e.g. 10ms.
    #[arg(short = 'i', long, default_value = "10ms", value_parser = parse_duration)]
    interval: Duration,
    /// Per-echo timeout.
    #[arg(short = 'W', long, default_value = "1s", value_parser = parse_duration)]
    timeout: Duration,
    /// ICMP payload size in bytes (minimum 8, which holds the nonce).
    #[arg(short = 's', long, default_value_t = 56, value_parser = clap::value_parser!(u16).range(8..))]
    size: u16,
    /// Pass if the p99 of |api - raw| is at most this many milliseconds.
    #[arg(long, default_value_t = 0.5)]
    max_p99_ms: f64,
}

pub(crate) fn run(args: &CalibrateArgs) -> ExitCode {
    if args.timeout.is_zero() {
        eprintln!("routelith ctl calibrate: the timeout must be greater than zero");
        return ExitCode::from(2);
    }
    #[cfg(windows)]
    {
        let pairs = match rl_probe::calibration::run(
            args.target,
            args.count,
            args.interval,
            args.timeout,
            usize::from(args.size),
        ) {
            Ok(pairs) => pairs,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "routelith ctl calibrate: the raw-socket reference needs Administrator ({e})"
                );
                return ExitCode::from(2);
            }
            Err(e) => {
                eprintln!("routelith ctl calibrate: {e}");
                return ExitCode::from(2);
            }
        };
        let summary = Summary::from_pairs(&pairs);
        let (report, verdict) = render(args, &summary);
        print!("{report}");
        match verdict {
            Some(true) => ExitCode::SUCCESS,
            Some(false) => ExitCode::from(1),
            None => ExitCode::from(2),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("routelith ctl calibrate: only needed and supported on Windows");
        ExitCode::from(2)
    }
}

// Only called on Windows outside tests.
#[cfg_attr(not(windows), allow(dead_code))]
fn ms(us: i64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let v = us as f64 / 1000.0;
    format!("{v:.3}")
}

// Only called on Windows outside tests.
#[cfg_attr(not(windows), allow(dead_code))]
fn line(out: &mut String, label: &str, d: Option<Dist>) {
    match d {
        Some(d) => {
            let _ = writeln!(
                out,
                "{label:<26} min/median/p90/p99/max = {}/{}/{}/{}/{} ms (n={})",
                ms(d.min),
                ms(d.median),
                ms(d.p90),
                ms(d.p99),
                ms(d.max),
                d.count
            );
        }
        None => {
            let _ = writeln!(out, "{label:<26} no replies");
        }
    }
}

/// The report, and the verdict (`None` if there were no complete pairs).
// Only called on Windows outside tests.
#[cfg_attr(not(windows), allow(dead_code))]
fn render(args: &CalibrateArgs, s: &Summary) -> (String, Option<bool>) {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "calibration {}: {} pairs, {}-byte payload, {:?} apart",
        args.target, s.pairs, args.size, args.interval
    );
    line(&mut out, "icmp api (IcmpSendEcho2Ex)", s.api);
    line(&mut out, "raw socket reference", s.raw);
    line(&mut out, "api - raw", s.diff);
    line(&mut out, "|api - raw|", s.abs_err);
    line(&mut out, "|api - raw - offset|", s.abs_err_corrected);
    let _ = writeln!(
        out,
        "api RoundTripTime field more than 1 ms off the reference: {} of {} pairs",
        s.api_field_off,
        s.diff.map_or(0, |d| d.count)
    );
    let Some(err) = s.abs_err else {
        let _ = writeln!(out, "FAIL  no pair had replies on both sides");
        return (out, None);
    };
    // Compare in the same unit without rounding the limit.
    #[allow(clippy::cast_precision_loss)]
    let pass = err.p99 as f64 <= args.max_p99_ms * 1000.0;
    let _ = writeln!(
        out,
        "{}  R1: p99 |api - raw| = {} ms, target <= {} ms",
        if pass { "PASS" } else { "FAIL" },
        ms(err.p99),
        args.max_p99_ms
    );
    (out, Some(pass))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rl_probe::calibration::Pair;

    fn args() -> CalibrateArgs {
        CalibrateArgs {
            target: Ipv4Addr::LOCALHOST,
            count: 2,
            interval: Duration::from_millis(10),
            timeout: Duration::from_secs(1),
            size: 56,
            max_p99_ms: 0.5,
        }
    }

    fn pair(api_us: u64, raw_us: u64) -> Pair {
        Pair {
            api: Some(Duration::from_micros(api_us)),
            api_rtt_ms: Some(0),
            raw: Some(Duration::from_micros(raw_us)),
        }
    }

    #[test]
    fn verdict_follows_the_p99_limit() {
        let ok = Summary::from_pairs(&[pair(300, 100), pair(400, 100)]);
        let (out, verdict) = render(&args(), &ok);
        assert_eq!(verdict, Some(true), "{out}");
        assert!(
            out.contains("PASS  R1: p99 |api - raw| = 0.300 ms"),
            "{out}"
        );

        let bad = Summary::from_pairs(&[pair(300, 100), pair(900, 100)]);
        assert_eq!(render(&args(), &bad).1, Some(false));
    }

    #[test]
    fn no_complete_pair_is_an_error() {
        let s = Summary::from_pairs(&[Pair {
            api: None,
            api_rtt_ms: None,
            raw: None,
        }]);
        let (out, verdict) = render(&args(), &s);
        assert_eq!(verdict, None);
        assert!(out.contains("no replies"), "{out}");
    }
}
