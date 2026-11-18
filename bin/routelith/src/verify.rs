//! `routelith ctl verify`: validate a configuration file without starting
//! anything (architecture doc §13.1).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Args;
use rl_core::config::{self, Config, Family, Severity};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Args)]
pub(crate) struct VerifyArgs {
    /// Path to the TOML configuration file.
    config: PathBuf,
    /// Skip the DNS lookup of every host name.
    #[arg(long)]
    no_resolve: bool,
}

/// Exit codes: 0 valid (warnings allowed), 1 invalid, 2 file unreadable.
pub(crate) async fn run(args: VerifyArgs) -> ExitCode {
    let src = match std::fs::read_to_string(&args.config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("routelith ctl verify: {}: {e}", args.config.display());
            return ExitCode::from(2);
        }
    };
    let parsed = config::parse(&src);
    let file = args.config.display();
    for d in &parsed.diagnostics {
        eprintln!("{file}:{d}");
    }
    let Some(cfg) = parsed.config else {
        let n = parsed.errors().count();
        eprintln!(
            "{file}: invalid ({n} error{})",
            if n == 1 { "" } else { "s" }
        );
        return ExitCode::from(1);
    };

    let mut warnings = parsed
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .count();
    warnings += check_privileges(&cfg, &args.config);
    if !args.no_resolve {
        warnings += check_hosts(&cfg, &args.config).await;
    }
    println!("{}", summary(&cfg, warnings));
    ExitCode::SUCCESS
}

fn summary(cfg: &Config, warnings: usize) -> String {
    let series: u32 = cfg.targets.iter().map(|t| t.family.series()).sum();
    let pps: f64 = cfg
        .targets
        .iter()
        .map(|t| t.schedule.pps() * f64::from(t.family.series()))
        .sum();
    format!(
        "OK: {} target{}, {series} series, {pps:.1} of {} packets/s on average, vantage {:?}{}",
        cfg.targets.len(),
        if cfg.targets.len() == 1 { "" } else { "s" },
        cfg.server.max_pps,
        cfg.server.vantage,
        match warnings {
            0 => String::new(),
            1 => ", 1 warning".to_string(),
            n => format!(", {n} warnings"),
        }
    )
}

/// Warn when this user may not open the ICMP sockets the targets need.
fn check_privileges(cfg: &Config, path: &Path) -> usize {
    let needs = |v6: bool| {
        cfg.targets.iter().any(|t| match t.family {
            Family::V4 => !v6,
            Family::V6 => v6,
            Family::Both | Family::PreferV6 => true,
        })
    };
    let mut warnings = 0;
    for v6 in [false, true].into_iter().filter(|&v6| needs(v6)) {
        if let Err(e) = rl_probe::check_permission(v6) {
            eprintln!(
                "{}: warning: this user cannot send ICMPv{}: {e}",
                path.display(),
                if v6 { 6 } else { 4 }
            );
            warnings += 1;
        }
    }
    warnings
}

/// Warn for every host name that does not resolve to an address of its family.
async fn check_hosts(cfg: &Config, path: &Path) -> usize {
    let mut tasks = tokio::task::JoinSet::new();
    for t in &cfg.targets {
        if t.host.parse::<IpAddr>().is_ok() {
            continue;
        }
        let (host, family, line) = (t.host.clone(), t.family, t.line);
        tasks.spawn(async move {
            let lookup =
                tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host.as_str(), 0)));
            let problem = match lookup.await {
                Err(_) => Some("lookup timed out".to_string()),
                Ok(Err(e)) => Some(e.to_string()),
                Ok(Ok(addrs)) => {
                    let addrs: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                    missing_family(family, &addrs)
                }
            };
            problem.map(|p| (line, host, p))
        });
    }
    let mut problems: Vec<(usize, String, String)> = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some(p)) = joined {
            problems.push(p);
        }
    }
    problems.sort();
    for (line, host, problem) in &problems {
        eprintln!(
            "{}:{line}: warning: host {host:?} does not resolve: {problem}",
            path.display()
        );
    }
    problems.len()
}

/// What is missing from `addrs` for `family`, if anything.
fn missing_family(family: Family, addrs: &[IpAddr]) -> Option<String> {
    let v4 = addrs.iter().any(IpAddr::is_ipv4);
    let v6 = addrs.iter().any(IpAddr::is_ipv6);
    match family {
        Family::V4 if !v4 => Some("no IPv4 address".into()),
        Family::V6 if !v6 => Some("no IPv6 address".into()),
        Family::Both if !(v4 && v6) => Some(format!(
            "family \"both\" needs IPv4 and IPv6 addresses, found only IPv{}",
            if v4 { 4 } else { 6 }
        )),
        Family::PreferV6 if !(v4 || v6) => Some("no address".into()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_coverage() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(missing_family(Family::V4, &[v4]), None);
        assert!(missing_family(Family::V6, &[v4]).is_some());
        assert!(missing_family(Family::Both, &[v6]).is_some());
        assert_eq!(missing_family(Family::Both, &[v4, v6]), None);
        assert_eq!(missing_family(Family::PreferV6, &[v4]), None);
    }

    #[test]
    fn summary_counts_series_and_rate() {
        let src = "[server]\ndata_dir = \"/x\"\n[[group]]\nname = \"G\"\n\
                   [[group.target]]\nname = \"a\"\nhost = \"h\"\nfamily = \"both\"\n";
        let cfg = config::parse(src).config.unwrap();
        assert_eq!(
            summary(&cfg, 1),
            "OK: 1 target, 2 series, 0.1 of 1000 packets/s on average, vantage \"local\", 1 warning"
        );
    }
}
