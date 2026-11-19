//! `routelith ctl render`: draw a smoke graph from the raw tier as SVG
//! (architecture doc §7.1, §21.2).

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, ValueEnum};
use rl_core::config::{self, Config};
use rl_render::{Graph, Round};
use rl_store::{Reader, SeriesKey};

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("source").required(true).args(["config", "data_dir"])))]
pub(crate) struct RenderArgs {
    /// Target id as configured.
    #[arg(long)]
    target: String,
    /// Time range to draw, ending now (or at --end).
    #[arg(long, value_enum, default_value_t = Range::H3)]
    range: Range,
    /// Output SVG file.
    #[arg(long)]
    out: PathBuf,
    /// Configuration file, for the data directory and vantage.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Data directory, instead of --config.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Vantage that measured the target (default: the config's, or the
    /// only one in the store).
    #[arg(long)]
    vantage: Option<String>,
    /// Series of a `both` target: v4 or v6 (default: v4).
    #[arg(long)]
    family: Option<String>,
    /// End of the range, Unix seconds (default: now).
    #[arg(long, hide = true)]
    end: Option<i64>,
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

impl Range {
    fn ms(self) -> i64 {
        const HOUR: i64 = 3_600_000;
        match self {
            Self::H3 => 3 * HOUR,
            Self::H30 => 30 * HOUR,
            Self::D10 => 240 * HOUR,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::H3 => "3h",
            Self::H30 => "30h",
            Self::D10 => "10d",
        }
    }
}

/// Exit codes: 0 written, 1 no such target, 2 cannot read or write.
pub(crate) fn run(args: &RenderArgs) -> ExitCode {
    match render(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, msg)) => {
            eprintln!("routelith ctl render: {msg}");
            ExitCode::from(code)
        }
    }
}

fn render(args: &RenderArgs) -> Result<(), (u8, String)> {
    let (data_dir, cfg) = source(args)?;
    let cfg_vantage = cfg.as_ref().map(|c| c.server.vantage.clone());
    let reader =
        Reader::open(&data_dir).map_err(|e| (2, format!("{}: {e}", data_dir.display())))?;
    let key = pick_series(
        reader.find(&args.target),
        &args.target,
        args.vantage.as_deref().or(cfg_vantage.as_deref()),
        args.family.as_deref(),
    )
    .map_err(|m| (1, m))?;
    let (key, id) = key;

    let to_ms = match args.end {
        Some(s) => end_ms(s).ok_or_else(|| {
            (
                2,
                format!("--end {s} is outside the years 0000 to 9999 the store covers"),
            )
        })?,
        None => now_ms(),
    };
    let from_ms = to_ms - args.range.ms();
    let rounds = reader
        .read(id, from_ms, to_ms)
        .map_err(|e| (2, format!("reading {key}: {e}")))?;
    let view: Vec<Round<'_>> = rounds
        .iter()
        .map(|r| Round {
            ts_ms: r.ts_ms,
            sent: r.sent,
            rtts_us: &r.rtts_us,
        })
        .collect();
    let title = format!("{} ({}, from {})", key.target, key.family, key.vantage);
    let svg = rl_render::render(
        &view,
        &Graph {
            title: &title,
            from_ms,
            to_ms,
            // The config's step, else the one the server recorded (§21.3 E5).
            step_ms: bucket_step(
                configured_step(cfg.as_ref(), &key)
                    .or_else(|| reader.step_ms(id).and_then(|s| i64::try_from(s).ok())),
                smallest_gap(&rounds),
            ),
            width: Graph::DEFAULT_WIDTH,
            height: Graph::DEFAULT_HEIGHT,
        },
    );
    std::fs::write(&args.out, svg).map_err(|e| (2, format!("{}: {e}", args.out.display())))?;
    eprintln!(
        "routelith ctl render: {} rounds of {key} over {} written to {}",
        rounds.len(),
        args.range.name(),
        args.out.display()
    );
    Ok(())
}

/// Data directory and vantage from --config or --data-dir.
fn source(args: &RenderArgs) -> Result<(PathBuf, Option<Config>), (u8, String)> {
    if let Some(dir) = &args.data_dir {
        return Ok((dir.clone(), None));
    }
    let path = args
        .config
        .as_ref()
        .ok_or((2, "need --config or --data-dir".to_string()))?;
    let src = std::fs::read_to_string(path).map_err(|e| (2, format!("{}: {e}", path.display())))?;
    let parsed = config::parse(&src);
    let cfg = parsed.config.ok_or_else(|| {
        (
            2,
            format!(
                "{} is invalid; check it with `routelith ctl verify`",
                path.display()
            ),
        )
    })?;
    Ok((cfg.server.data_dir.clone(), Some(cfg)))
}

/// `--end` in Unix milliseconds, if it falls in the years 0000 to 9999.
fn end_ms(secs: i64) -> Option<i64> {
    // 0000-01-01T00:00:00Z and 9999-12-31T23:59:59Z.
    const MIN_S: i64 = -62_167_219_200;
    const MAX_S: i64 = 253_402_300_799;
    (MIN_S..=MAX_S).contains(&secs).then(|| secs * 1000)
}

/// The step the configuration gives the series, when the configuration
/// describes it (same vantage, a target with that id).
fn configured_step(cfg: Option<&Config>, key: &SeriesKey) -> Option<i64> {
    let cfg = cfg.filter(|c| c.server.vantage == key.vantage)?;
    let t = cfg.targets.iter().find(|t| t.id == key.target)?;
    i64::try_from(t.schedule.step.as_millis()).ok()
}

/// The column step for a series. A configured step at least as long as
/// the smallest spacing of the stored rounds is kept (a stray close pair
/// must not shrink the columns). One shorter is not: the rounds were taken
/// at a slower step than configured now, and columns on the new step would
/// leave gaps between them, so the stored spacing is used instead.
fn bucket_step(configured: Option<i64>, smallest_gap: Option<i64>) -> Option<i64> {
    match (configured, smallest_gap) {
        (Some(step), Some(gap)) if step < gap => Some(gap),
        (step, _) => step,
    }
}

/// The smallest spacing of the stored rounds.
fn smallest_gap(rounds: &[rl_store::StoredRound]) -> Option<i64> {
    rounds
        .windows(2)
        .map(|w| w[1].ts_ms - w[0].ts_ms)
        .filter(|&d| d > 0)
        .min()
}

/// The one series of `target` matching the filters.
fn pick_series(
    found: Vec<(&SeriesKey, u64)>,
    target: &str,
    vantage: Option<&str>,
    family: Option<&str>,
) -> Result<(SeriesKey, u64), String> {
    if found.is_empty() {
        return Err(format!("no data for target {target:?}"));
    }
    let list = |v: &[(&SeriesKey, u64)]| {
        v.iter()
            .map(|(k, _)| k.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let all = list(&found);
    let mut cands: Vec<(&SeriesKey, u64)> = found
        .into_iter()
        .filter(|(k, _)| vantage.is_none_or(|v| k.vantage == v))
        .collect();
    if cands.is_empty() {
        return Err(format!(
            "target {target:?} has no data from vantage {:?} (it has: {all})",
            vantage.unwrap_or_default()
        ));
    }
    match family {
        Some(f) => cands.retain(|(k, _)| k.family == f),
        // A `both` target: draw IPv4 unless asked otherwise. Several
        // vantages are a choice for the user, not a default.
        None if cands.len() > 1
            && cands.iter().all(|(k, _)| k.vantage == cands[0].0.vantage)
            && cands.iter().any(|(k, _)| k.family == "v4") =>
        {
            cands.retain(|(k, _)| k.family == "v4");
        }
        None => {}
    }
    match cands.as_slice() {
        [(k, id)] => Ok(((*k).clone(), *id)),
        [] => Err(format!(
            "target {target:?} has no {} series (it has: {all})",
            family.unwrap_or_default()
        )),
        more => Err(format!(
            "target {target:?} has several series ({}); choose with --vantage or --family",
            list(more)
        )),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn series_choice() {
        let a = SeriesKey::new("local", "gw", "v4");
        let b = SeriesKey::new("local", "gw", "v6");
        let c = SeriesKey::new("remote", "gw", "v4");
        let found = || vec![(&a, 1), (&b, 2), (&c, 3)];
        assert_eq!(
            pick_series(found(), "gw", Some("local"), None).unwrap().1,
            1
        );
        assert_eq!(
            pick_series(found(), "gw", Some("local"), Some("v6"))
                .unwrap()
                .1,
            2
        );
        assert!(
            pick_series(found(), "gw", None, None)
                .unwrap_err()
                .contains("several")
        );
        // Two vantages, no family: listed, not settled by the IPv4 default.
        let d = SeriesKey::new("remote", "gw", "v6");
        assert!(
            pick_series(vec![(&a, 1), (&d, 4)], "gw", None, None)
                .unwrap_err()
                .contains("several")
        );
        assert!(
            pick_series(found(), "gw", Some("x"), None)
                .unwrap_err()
                .contains("vantage")
        );
        assert!(
            pick_series(vec![], "gw", None, None)
                .unwrap_err()
                .contains("no data")
        );
    }

    #[test]
    fn end_times_outside_the_store_years_are_refused() {
        assert_eq!(end_ms(0), Some(0));
        assert_eq!(end_ms(1_763_424_000), Some(1_763_424_000_000));
        assert_eq!(end_ms(i64::MIN), None);
        assert_eq!(end_ms(i64::MAX), None);
        assert_eq!(end_ms(253_402_300_800), None);
    }

    #[test]
    fn the_configured_step_applies_to_its_own_series() {
        let src = "[server]\ndata_dir = \"/x\"\n[defaults]\nstep = \"60s\"\n[[group]]\n\
                   name = \"G\"\n[[group.target]]\nname = \"gw\"\nhost = \"192.0.2.1\"\n";
        let cfg = config::parse(src).config.unwrap();
        let id = cfg.targets[0].id.clone();
        let own = SeriesKey::new("local", &id, "v4");
        let other_vantage = SeriesKey::new("remote", &id, "v4");
        assert_eq!(configured_step(Some(&cfg), &own), Some(60_000));
        assert_eq!(configured_step(Some(&cfg), &other_vantage), None);
        assert_eq!(configured_step(None, &own), None);
    }

    #[test]
    fn rounds_stored_at_a_slower_step_keep_their_own_spacing() {
        // Stored every 10 min, configured every minute now: 10 min columns.
        assert_eq!(bucket_step(Some(60_000), Some(600_000)), Some(600_000));
        // Configured step at or above the stored spacing is kept.
        assert_eq!(bucket_step(Some(600_000), Some(60_000)), Some(600_000));
        assert_eq!(bucket_step(Some(60_000), Some(60_000)), Some(60_000));
        // Nothing configured: the renderer infers the step itself.
        assert_eq!(bucket_step(None, Some(600_000)), None);
        assert_eq!(bucket_step(Some(60_000), None), Some(60_000));
    }

    #[test]
    fn the_smallest_gap_between_stored_rounds() {
        let at = |ts_ms| rl_store::StoredRound {
            ts_ms,
            sent: 1,
            rtts_us: vec![1000],
            errors: rl_store::ErrorCounts::default(),
            resolved: None,
            timing: None,
            flags: 0,
        };
        let rounds = [at(0), at(300_000), at(600_000), at(600_500)];
        assert_eq!(smallest_gap(&rounds), Some(500));
        assert_eq!(smallest_gap(&rounds[..3]), Some(300_000));
        assert_eq!(smallest_gap(&rounds[..1]), None);
    }

    #[test]
    fn renders_from_a_data_directory() {
        use rl_store::{ErrorCounts, StoredRound, Writer, WriterOptions};
        let dir = tempfile::tempdir().unwrap();
        let end_ms = 1_763_424_000_000;
        let (mut w, _) = Writer::open(dir.path(), WriterOptions::default(), end_ms).unwrap();
        let ids = w
            .register(&[
                SeriesKey::new("local", "gw", "v4"),
                SeriesKey::new("local", "gw", "v6"),
            ])
            .unwrap();
        for i in 0..36 {
            for &id in &ids {
                let round = StoredRound {
                    ts_ms: end_ms - 3 * 3_600_000 + i * 300_000,
                    sent: 5,
                    rtts_us: vec![900, 1000, 1100, 1200],
                    errors: ErrorCounts::default(),
                    resolved: None,
                    timing: None,
                    flags: 0,
                };
                w.append(id, round).unwrap();
            }
        }
        w.close().unwrap();
        let out = dir.path().join("gw.svg");
        let args = RenderArgs {
            target: "gw".into(),
            range: Range::H3,
            out: out.clone(),
            config: None,
            data_dir: Some(dir.path().to_path_buf()),
            vantage: None,
            family: None,
            end: Some(end_ms / 1000),
        };
        render(&args).unwrap();
        let svg = std::fs::read_to_string(&out).unwrap();
        assert!(svg.contains("gw (v4, from local)"), "{svg}");
        assert!(svg.contains("loss 20.00 %, 180 pings sent"), "{svg}");
        let missing = RenderArgs {
            target: "nope".into(),
            ..args
        };
        assert_eq!(render(&missing).unwrap_err().0, 1);
    }
}
