//! The local health snapshot log (architecture doc §19, §21.3 E13): one
//! sample of this machine's health a minute, per vantage, kept apart from
//! the series so the segment format is unchanged.
//!
//! ```text
//! data/health/<vantage>/2026-11-19.jsonl    one JSON object per line
//! ```
//!
//! Samples are small and written once a minute, so a plain append-only
//! JSON-lines file per UTC day is enough: a torn last line after a crash
//! is skipped when read, and retention deletes whole day files.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::StoreError;
use crate::layout::{self, date, day_of, parse_date};

/// Errors and drops of one interface during a sample's interval.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicDelta {
    pub name: String,
    pub errors: u64,
    pub drops: u64,
}

/// One health sample: the interval ending at `t`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HealthSample {
    /// End of the interval, Unix milliseconds.
    pub t: i64,
    /// Length of the interval in milliseconds; 0 for the first sample after
    /// start-up, which has no counters to compare against.
    #[serde(default)]
    pub interval_ms: i64,
    /// CPU busy during the interval, percent of all CPUs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f64>,
    /// One-minute load average at `t` (Linux).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load1: Option<f64>,
    /// When the NIC counters could not be read for a while, the longer
    /// span (ms) their deltas below cover instead of `interval_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic_interval_ms: Option<i64>,
    /// Receive and transmit errors on all interfaces during the interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic_errors: Option<u64>,
    /// Dropped packets on all interfaces during the interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic_drops: Option<u64>,
    /// The interfaces that had errors or drops.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nics: Vec<NicDelta>,
    /// Default gateways at `t`.
    #[serde(default)]
    pub gateways: Vec<IpAddr>,
    /// DNS servers at `t`.
    #[serde(default)]
    pub dns: Vec<IpAddr>,
}

/// `data/health/<vantage>`.
pub fn health_dir(dir: &Path, vantage: &str) -> PathBuf {
    dir.join("health").join(vantage)
}

fn day_path(dir: &Path, day: i64) -> PathBuf {
    dir.join(format!("{}.jsonl", date(day)))
}

fn check_vantage(vantage: &str) -> Result<(), StoreError> {
    let ok = !vantage.is_empty()
        && vantage != "."
        && vantage != ".."
        && vantage
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(StoreError::InvalidKey(vantage.to_string()))
    }
}

/// Day files in a health directory, oldest first.
fn list_days(dir: &Path) -> std::io::Result<Vec<i64>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut days = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        if let Some(day) = name
            .to_str()
            .and_then(|n| n.strip_suffix(".jsonl"))
            .and_then(parse_date)
        {
            days.push(day);
        }
    }
    days.sort_unstable();
    Ok(days)
}

/// Appends samples for one vantage.
#[derive(Debug)]
pub struct HealthLog {
    dir: PathBuf,
    keep_days: i64,
    /// Day of the last retention pass.
    expired_at: Option<i64>,
    /// Files deleted by retention.
    pub expired_files: u64,
    /// A day file was created and its directory entry is not yet synced
    /// (an append failed after creating it).
    dir_unsynced: bool,
}

impl HealthLog {
    /// `keep_days` whole UTC days are kept besides today (the raw tier's
    /// 30 days by default).
    pub fn open(data_dir: &Path, vantage: &str, keep_days: i64) -> Result<Self, StoreError> {
        check_vantage(vantage)?;
        if keep_days < 1 {
            return Err(StoreError::InvalidOptions(
                "health retention must be at least one day",
            ));
        }
        let dir = health_dir(data_dir, vantage);
        std::fs::create_dir_all(&dir)?;
        // Make the names leading to it durable, whether this call created
        // them or an earlier one that failed before syncing did.
        for d in [dir.parent(), Some(data_dir)].into_iter().flatten() {
            layout::sync_dir(d)?;
        }
        Ok(Self {
            dir,
            keep_days,
            expired_at: None,
            expired_files: 0,
            // A day file left by a run that stopped before syncing its
            // name: sync the directory on the first append regardless.
            dir_unsynced: true,
        })
    }

    /// Append one sample to its day's file and make it durable.
    pub fn append(&mut self, s: &HealthSample) -> Result<(), StoreError> {
        let day = day_of(s.t);
        if !(layout::MIN_DAY..=layout::MAX_DAY).contains(&day) {
            return Err(StoreError::InvalidRound("health sample time out of range"));
        }
        let path = day_path(&self.dir, day);
        let new = !path.exists();
        self.dir_unsynced |= new;
        let mut f = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;
        let mut line = Vec::with_capacity(256);
        // A line torn by a crash would swallow this one: start on a new line.
        if !new && !ends_with_newline(&mut f)? {
            line.push(b'\n');
        }
        serde_json::to_writer(&mut line, s)
            .map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
        line.push(b'\n');
        f.write_all(&line)?;
        f.sync_data()?;
        if self.dir_unsynced {
            layout::sync_dir(&self.dir)?;
            self.dir_unsynced = false;
        }
        if self.expired_at != Some(day) {
            self.expire(day)?;
            self.expired_at = Some(day);
        }
        Ok(())
    }

    fn expire(&mut self, today: i64) -> Result<(), StoreError> {
        let mut removed = false;
        for day in list_days(&self.dir)? {
            if day < today.saturating_sub(self.keep_days) {
                std::fs::remove_file(day_path(&self.dir, day))?;
                self.expired_files += 1;
                removed = true;
            }
        }
        if removed {
            layout::sync_dir(&self.dir)?;
        }
        Ok(())
    }
}

fn ends_with_newline(f: &mut File) -> std::io::Result<bool> {
    let len = f.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(true);
    }
    f.seek(SeekFrom::End(-1))?;
    let mut b = [0u8; 1];
    f.read_exact(&mut b)?;
    Ok(b[0] == b'\n')
}

/// Samples of `vantage` with `from <= t < to`, oldest first. Lines that do
/// not parse (a write torn by a crash) are skipped.
pub fn read_health(
    data_dir: &Path,
    vantage: &str,
    from: i64,
    to: i64,
) -> Result<Vec<HealthSample>, StoreError> {
    check_vantage(vantage)?;
    let dir = health_dir(data_dir, vantage);
    let mut out = Vec::new();
    if from >= to {
        return Ok(out);
    }
    let (first, last) = (day_of(from), day_of(to - 1));
    for day in list_days(&dir)? {
        if day < first || day > last {
            continue;
        }
        let f = match File::open(day_path(&dir, day)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        for line in BufReader::new(f).split(b'\n') {
            let line = line?;
            if let Ok(s) = serde_json::from_slice::<HealthSample>(&line) {
                if (from..to).contains(&s.t) {
                    out.push(s);
                }
            }
        }
    }
    out.sort_by_key(|s| s.t);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: i64 = 60_000;
    const DAY: i64 = 86_400_000;
    const T0: i64 = 1_763_510_400_000; // 2025-11-19T00:00:00Z

    fn sample(t: i64) -> HealthSample {
        HealthSample {
            t,
            interval_ms: MIN,
            nic_interval_ms: None,
            cpu_pct: Some(12.5),
            load1: Some(0.25),
            nic_errors: Some(1),
            nic_drops: Some(3),
            nics: vec![NicDelta {
                name: "Ethernet 2".into(),
                errors: 1,
                drops: 3,
            }],
            gateways: vec!["192.0.2.1".parse().unwrap()],
            dns: vec![
                "192.0.2.53".parse().unwrap(),
                "2001:db8::53".parse().unwrap(),
            ],
        }
    }

    #[test]
    fn samples_round_trip_across_days() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = HealthLog::open(tmp.path(), "local", 30).unwrap();
        for i in 0..3 {
            log.append(&sample(T0 + DAY - MIN + i * MIN)).unwrap();
        }
        let got = read_health(tmp.path(), "local", T0, T0 + 2 * DAY).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], sample(T0 + DAY - MIN));
        assert!(
            health_dir(tmp.path(), "local")
                .join("2025-11-19.jsonl")
                .exists()
        );
        assert!(
            health_dir(tmp.path(), "local")
                .join("2025-11-20.jsonl")
                .exists()
        );
        // `to` is exclusive, and other vantages are separate.
        let got = read_health(tmp.path(), "local", T0, T0 + DAY).unwrap();
        assert_eq!(got.len(), 1);
        assert!(
            read_health(tmp.path(), "other", T0, T0 + 2 * DAY)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_torn_line_loses_only_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = HealthLog::open(tmp.path(), "local", 30).unwrap();
        log.append(&sample(T0)).unwrap();
        let path = health_dir(tmp.path(), "local").join("2025-11-19.jsonl");
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"t\":17635104").unwrap();
        drop(f);
        log.append(&sample(T0 + 2 * MIN)).unwrap();
        let got = read_health(tmp.path(), "local", T0, T0 + DAY).unwrap();
        assert_eq!(
            got.iter().map(|s| s.t).collect::<Vec<_>>(),
            [T0, T0 + 2 * MIN]
        );
    }

    #[test]
    fn old_days_are_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = HealthLog::open(tmp.path(), "local", 2).unwrap();
        for d in 0..5 {
            log.append(&sample(T0 + d * DAY)).unwrap();
        }
        let days = list_days(&health_dir(tmp.path(), "local")).unwrap();
        assert_eq!(days.len(), 3);
        assert_eq!(days[0], day_of(T0 + 2 * DAY));
        assert_eq!(log.expired_files, 2);
    }

    #[test]
    fn a_vantage_cannot_escape_the_directory() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in ["", "..", "a/b", "a\\b"] {
            assert!(HealthLog::open(tmp.path(), bad, 30).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn missing_fields_read_as_empty() {
        let s: HealthSample = serde_json::from_str("{\"t\":5}").unwrap();
        assert_eq!(
            s,
            HealthSample {
                t: 5,
                ..HealthSample::default()
            }
        );
    }
}
