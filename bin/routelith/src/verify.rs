//! `routelith ctl verify`: validate a configuration file without starting
//! anything (architecture doc §13.1).

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Args;
use rl_core::config::{self, Config, Family, Severity, TargetConfig};
use tokio::sync::Semaphore;

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
    let file = args.config.display();
    let bytes = match std::fs::read(&args.config) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("routelith ctl verify: {file}: {e}");
            return ExitCode::from(2);
        }
    };
    let src = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{file}: error: not valid UTF-8 (byte {}); TOML files must be UTF-8",
                e.utf8_error().valid_up_to()
            );
            eprintln!("{file}: invalid (1 error)");
            return ExitCode::from(1);
        }
    };
    let parsed = config::parse(&src);
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
    let resolved = if args.no_resolve {
        HashMap::new()
    } else {
        let (resolved, n) = check_hosts(&cfg, &args.config).await;
        warnings += n;
        resolved
    };
    warnings += check_privileges(&cfg, &resolved, &args.config);
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

/// Address families a target will use: `(v4, v6)`.
///
/// `prefer-v6` uses IPv6 when its host has an IPv6 address, else IPv4, so it
/// needs the family its addresses select; `None` when that is unknown (not
/// resolved).
fn families_used(t: &TargetConfig, addrs: Option<&[IpAddr]>) -> Option<(bool, bool)> {
    match t.family {
        Family::V4 => Some((true, false)),
        Family::V6 => Some((false, true)),
        Family::Both => Some((true, true)),
        Family::PreferV6 => {
            let literal = t.host.parse::<IpAddr>().ok();
            let addrs = match (&literal, addrs) {
                (Some(a), _) => std::slice::from_ref(a),
                (None, Some(a)) => a,
                (None, None) => return None,
            };
            let v6 = addrs.iter().any(IpAddr::is_ipv6);
            let v4 = !v6 && addrs.iter().any(IpAddr::is_ipv4);
            Some((v4, v6))
        }
    }
}

/// Warn when this user may not open the ICMP sockets the targets need.
fn check_privileges(cfg: &Config, resolved: &HashMap<usize, Vec<IpAddr>>, path: &Path) -> usize {
    // For each family: needed for certain, or only by prefer-v6 targets
    // whose addresses are unknown.
    let (mut need, mut maybe) = ([false; 2], [false; 2]);
    for (i, t) in cfg.targets.iter().enumerate() {
        match families_used(t, resolved.get(&i).map(Vec::as_slice)) {
            Some((v4, v6)) => {
                need[0] |= v4;
                need[1] |= v6;
            }
            None => maybe = [true; 2],
        }
    }
    let mut warnings = 0;
    for (i, v6) in [false, true].into_iter().enumerate() {
        if !need[i] && !maybe[i] {
            continue;
        }
        if let Err(e) = rl_probe::check_permission(v6) {
            let n = if v6 { 6 } else { 4 };
            if need[i] {
                eprintln!(
                    "{}: warning: this user cannot send ICMPv{n}: {e}",
                    path.display()
                );
            } else {
                eprintln!(
                    "{}: warning: this user cannot send ICMPv{n}, which prefer-v6 targets \
                     use when their host has {} address: {e}",
                    path.display(),
                    if v6 { "an IPv6" } else { "only an IPv4" }
                );
            }
            warnings += 1;
        }
    }
    warnings
}

/// Lookups running at once; the rest wait without using their timeout.
const RESOLVE_PARALLEL: usize = 16;
/// All lookups together; any still unfinished are reported as unchecked.
const RESOLVE_ALL: Duration = Duration::from_secs(30);

/// Resolve every host name, warning for each that does not resolve to an
/// address of its family. Returns the addresses of each lookup that
/// succeeded, by index in `cfg.targets`, and the number of warnings.
async fn check_hosts(cfg: &Config, path: &Path) -> (HashMap<usize, Vec<IpAddr>>, usize) {
    let permits = Arc::new(Semaphore::new(RESOLVE_PARALLEL));
    let mut tasks = tokio::task::JoinSet::new();
    let mut pending: HashMap<usize, (usize, String)> = HashMap::new();
    let mut task_target: HashMap<tokio::task::Id, usize> = HashMap::new();
    for (i, t) in cfg.targets.iter().enumerate() {
        if t.host.parse::<IpAddr>().is_ok() {
            continue;
        }
        let (host, family) = (t.host.clone(), t.family);
        pending.insert(i, (t.line, host.clone()));
        let permits = permits.clone();
        let handle = tasks.spawn(async move {
            // The deadline starts once the lookup may run, and a timed-out
            // lookup keeps its permit until the system resolver returns.
            let permit = permits.acquire_owned().await.ok();
            let blocking = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                (host.as_str(), 0).to_socket_addrs()
            });
            let result = match tokio::time::timeout(RESOLVE_TIMEOUT, blocking).await {
                Err(_) => Err("lookup timed out".to_string()),
                Ok(Err(e)) => Err(format!("lookup failed: {e}")),
                Ok(Ok(Err(e))) => Err(e.to_string()),
                Ok(Ok(Ok(it))) => Ok(it.map(|a| a.ip()).collect::<Vec<IpAddr>>()),
            };
            (i, family, result)
        });
        task_target.insert(handle.id(), i);
    }

    let mut problems: Vec<(usize, String, String)> = Vec::new();
    let mut resolved = HashMap::new();
    let deadline = tokio::time::Instant::now() + RESOLVE_ALL;
    loop {
        let joined = match tokio::time::timeout_at(deadline, tasks.join_next_with_id()).await {
            Ok(Some(joined)) => joined,
            Ok(None) | Err(_) => break,
        };
        let (i, family, result) = match joined {
            Ok((_, r)) => r,
            Err(e) => {
                // The lookup task itself failed (for example, no thread
                // could be started for it): report that, not a timeout.
                if let Some((line, host)) = task_target.get(&e.id()).and_then(|i| pending.remove(i))
                {
                    problems.push((
                        line,
                        host,
                        format!("not checked: the lookup task failed: {e}"),
                    ));
                }
                continue;
            }
        };
        let Some((line, host)) = pending.remove(&i) else {
            continue;
        };
        match result {
            Err(e) => problems.push((line, host, e)),
            Ok(addrs) => {
                if let Some(p) = missing_family(family, &addrs) {
                    problems.push((line, host, p));
                }
                // Only a lookup that found addresses tells which family a
                // prefer-v6 target will use.
                if !addrs.is_empty() {
                    resolved.insert(i, addrs);
                }
            }
        }
    }
    tasks.abort_all();
    for (line, host) in pending.into_values() {
        problems.push((
            line,
            host,
            format!(
                "not checked: lookups did not finish within {}",
                rl_core::duration::format(RESOLVE_ALL)
            ),
        ));
    }
    problems.sort();
    for (line, host, problem) in &problems {
        eprintln!(
            "{}:{line}: warning: host {host:?} does not resolve: {problem}",
            path.display()
        );
    }
    (resolved, problems.len())
}

/// What is missing from `addrs` for `family`, if anything.
fn missing_family(family: Family, addrs: &[IpAddr]) -> Option<String> {
    let v4 = addrs.iter().any(IpAddr::is_ipv4);
    let v6 = addrs.iter().any(IpAddr::is_ipv6);
    match family {
        Family::V4 if !v4 => Some("no IPv4 address".into()),
        Family::V6 if !v6 => Some("no IPv6 address".into()),
        Family::Both if !v4 && !v6 => Some("no IPv4 or IPv6 address".into()),
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
        assert_eq!(
            missing_family(Family::Both, &[]).as_deref(),
            Some("no IPv4 or IPv6 address")
        );
    }

    #[test]
    fn prefer_v6_needs_the_family_its_addresses_select() {
        let src = "[server]\ndata_dir = \"/x\"\n[[group]]\nname = \"G\"\n\
                   [[group.target]]\nname = \"a\"\nhost = \"h\"\nfamily = \"prefer-v6\"\n";
        let cfg = config::parse(src).config.unwrap();
        let t = &cfg.targets[0];
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(families_used(t, None), None);
        assert_eq!(families_used(t, Some(&[v4])), Some((true, false)));
        assert_eq!(families_used(t, Some(&[v4, v6])), Some((false, true)));
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
