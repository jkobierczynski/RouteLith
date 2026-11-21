//! On-disk layout (architecture doc §6.2) and UTC day arithmetic.
//!
//! ```text
//! data/
//! ├── meta.redb                 series index
//! ├── wal/00000001.wal          write-ahead log
//! ├── quarantine/               damaged WAL files recovery set aside
//! ├── health/<vantage>/2026-11-18.jsonl   health snapshots, one a minute
//! └── series/<id>/
//!     ├── raw/
//!     │   ├── 2026-11-17.seg    sealed day segment
//!     │   └── 2026-11-18.open   today's open segment
//!     ├── r1h/2026-11.roll      hourly rollups of a month
//!     └── r1d/2026.roll         daily rollups of a year
//! ```

use std::path::{Path, PathBuf};

pub(crate) const DAY_MS: i64 = 86_400_000;

/// Days since 1970-01-01 (UTC) of a Unix-millisecond timestamp.
pub fn day_of(ts_ms: i64) -> i64 {
    ts_ms.div_euclid(DAY_MS)
}

/// `YYYY-MM-DD` of a day number (proleptic Gregorian, H. Hinnant's
/// `civil_from_days`).
pub fn date(day: i64) -> String {
    let z = day + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// First and last day the store accepts: years 0000 to 9999, so file
/// names are always `YYYY-MM-DD`.
pub(crate) const MIN_DAY: i64 = -719_528;
pub(crate) const MAX_DAY: i64 = 2_932_896;

/// Inverse of [`date`] for years 0000 to 9999.
pub(crate) fn parse_date(s: &str) -> Option<i64> {
    let mut it = s.splitn(3, '-');
    let y = it.next()?;
    if y.len() != 4 || !y.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let y: i64 = y.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let day = civil_day(y, m, d);
    (date(day) == s).then_some(day)
}

/// Day number of a proleptic Gregorian date, any year; `m` 1 to 12.
pub(crate) fn civil_day(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub(crate) fn index_path(dir: &Path) -> PathBuf {
    dir.join("meta.redb")
}

/// Held by the writer while it runs (see `writer::lock_dir`).
pub(crate) fn lock_path(dir: &Path) -> PathBuf {
    dir.join("writer.lock")
}

pub(crate) fn wal_dir(dir: &Path) -> PathBuf {
    dir.join("wal")
}

/// Damaged WAL files, kept for the operator but out of the live WAL set.
pub(crate) fn quarantine_dir(dir: &Path) -> PathBuf {
    dir.join("quarantine")
}

/// The directory holding `path`'s entry: its parent, or `.` for a
/// single-component relative path.
pub(crate) fn parent_or_dot(path: &Path) -> PathBuf {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

pub(crate) fn wal_path(dir: &Path, seq: u64) -> PathBuf {
    wal_dir(dir).join(format!("{seq:08}.wal"))
}

/// Directory holding a series' raw segments.
pub fn raw_dir(dir: &Path, series: u64) -> PathBuf {
    dir.join("series").join(series.to_string()).join("raw")
}

pub(crate) fn segment_path(dir: &Path, series: u64, day: i64, sealed: bool) -> PathBuf {
    let ext = if sealed { "seg" } else { "open" };
    raw_dir(dir, series).join(format!("{}.{ext}", date(day)))
}

/// A segment file found on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SegmentFile {
    pub(crate) day: i64,
    pub(crate) sealed: bool,
    pub(crate) path: PathBuf,
}

/// Segment files of a series, by day. Unrelated files are ignored.
pub(crate) fn list_segments(dir: &Path, series: u64) -> std::io::Result<Vec<SegmentFile>> {
    let raw = raw_dir(dir, series);
    let entries = match std::fs::read_dir(&raw) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let (stem, sealed) = if let Some(s) = name.strip_suffix(".seg") {
            (s, true)
        } else if let Some(s) = name.strip_suffix(".open") {
            (s, false)
        } else {
            continue;
        };
        if let Some(day) = parse_date(stem) {
            out.push(SegmentFile {
                day,
                sealed,
                path: entry.path(),
            });
        }
    }
    out.sort_by_key(|s| (s.day, s.sealed));
    Ok(out)
}

/// File names of a series' segments, by day (for tools and tests).
pub fn segment_file_names(dir: &Path, series: u64) -> Vec<String> {
    list_segments(dir, series)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|s| s.path.file_name()?.to_str().map(str::to_string))
        .collect()
}

/// Series ids that have a directory under `series/`.
pub(crate) fn list_series_dirs(dir: &Path) -> std::io::Result<Vec<u64>> {
    let entries = match std::fs::read_dir(dir.join("series")) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        // Only the spelling `raw_dir` produces ("1", not "01").
        if let Some(id) = name
            .to_str()
            .and_then(|s| s.parse::<u64>().ok().filter(|id| id.to_string() == s))
        {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// WAL file sequence numbers present, ascending.
pub(crate) fn list_wal(dir: &Path) -> std::io::Result<Vec<u64>> {
    let entries = match std::fs::read_dir(wal_dir(dir)) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut seqs = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        // Only the spelling `wal_path` produces.
        if let Some(seq) = name.to_str().and_then(|n| {
            n.strip_suffix(".wal")
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|&seq| format!("{seq:08}.wal") == n)
        }) {
            seqs.push(seq);
        }
    }
    seqs.sort_unstable();
    Ok(seqs)
}

/// Make a rename or new file in `dir` durable.
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    // Windows: FlushFileBuffers on a directory handle opened for writing
    // with FILE_FLAG_BACKUP_SEMANTICS (the only way to open a directory)
    // flushes its metadata, including new and renamed entries.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)?
            .sync_all()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(20_410), "2025-11-18");
        assert_eq!(date(-1), "1969-12-31");
        assert_eq!(date(11_016), "2000-02-29");
        for day in 0..800_000 {
            if day % 997 == 0 {
                assert_eq!(parse_date(&date(day)), Some(day), "{day}");
            }
        }
        assert_eq!(parse_date("2025-02-30"), None);
        assert_eq!(parse_date("2025-13-01"), None);
        assert_eq!(parse_date("x"), None);
        assert_eq!(date(MIN_DAY), "0000-01-01");
        assert_eq!(date(MAX_DAY), "9999-12-31");
        assert_eq!(parse_date("0000-01-01"), Some(MIN_DAY));
        assert_eq!(parse_date("99999999999999-01-01"), None);
        assert_eq!(parse_date("-001-01-01"), None);
    }

    #[test]
    fn days_split_at_utc_midnight() {
        assert_eq!(day_of(DAY_MS - 1), 0);
        assert_eq!(day_of(DAY_MS), 1);
        assert_eq!(day_of(-1), -1);
    }
}
