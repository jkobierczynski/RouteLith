//! The event log (architecture doc §11.2, §21.5 F4): alerts raised and
//! cleared, address changes, server start and stop.
//!
//! ```text
//! data/events/2026-11-19.jsonl    one JSON object per line
//! ```
//!
//! Events are rare, so like the health log this is a plain append-only
//! JSON-lines file per UTC day, synced on every write: a torn last line
//! after a crash is skipped when read, and retention deletes whole days.
//! It is not in `meta.redb` because redb locks that whole file while it is
//! open, and readers (the API, reports) must not wait on the server.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::StoreError;
use crate::health::{day_path, ends_with_newline, list_days};
use crate::layout::{self, day_of};

/// Days kept besides today: long enough for a yearly report and the
/// NIS2 timeline of anything in the last year.
pub const EVENT_DAYS: i64 = 400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    AlertRaised,
    AlertCleared,
    /// A target resolved to a different address.
    IpChanged,
    ServerStarted,
    ServerStopped,
    /// A kind written by a newer version.
    #[serde(other)]
    Unknown,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::AlertRaised => "alert_raised",
            EventKind::AlertCleared => "alert_cleared",
            EventKind::IpChanged => "ip_changed",
            EventKind::ServerStarted => "server_started",
            EventKind::ServerStopped => "server_stopped",
            EventKind::Unknown => "unknown",
        }
    }
}

/// One event. Fields that do not apply to its kind are left out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// When it happened, Unix milliseconds: for an alert, the start of the
    /// round that raised or cleared it.
    pub t: i64,
    pub kind: EventKind,
    pub vantage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// `v4`, `v6` or `prefer-v6`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub series: Option<u64>,
    /// The alert rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// The value that raised or cleared the alert, in the rule's unit
    /// (ms, percent or MOS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// For a cleared alert, when it was raised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,
    /// For an address change, the old and new address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// One line for people.
    #[serde(default)]
    pub message: String,
}

impl Event {
    /// An event of `kind` with only the time, vantage and message set.
    pub fn new(t: i64, kind: EventKind, vantage: &str, message: impl Into<String>) -> Self {
        Self {
            t,
            kind,
            vantage: vantage.to_string(),
            target: None,
            family: None,
            series: None,
            rule: None,
            value: None,
            since: None,
            from: None,
            to: None,
            message: message.into(),
        }
    }
}

/// `data/events`.
pub fn events_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("events")
}

/// Appends events.
#[derive(Debug)]
pub struct EventLog {
    dir: PathBuf,
    keep_days: i64,
    expired_at: Option<i64>,
    /// Files deleted by retention.
    pub expired_files: u64,
    dir_unsynced: bool,
}

impl EventLog {
    /// `keep_days` whole UTC days are kept besides today.
    pub fn open(data_dir: &Path, keep_days: i64) -> Result<Self, StoreError> {
        if keep_days < 1 {
            return Err(StoreError::InvalidOptions(
                "event retention must be at least one day",
            ));
        }
        let dir = events_dir(data_dir);
        std::fs::create_dir_all(&dir)?;
        layout::sync_dir(data_dir)?;
        Ok(Self {
            dir,
            keep_days,
            expired_at: None,
            expired_files: 0,
            dir_unsynced: true,
        })
    }

    /// Append one event to its day's file and make it durable.
    pub fn append(&mut self, e: &Event) -> Result<(), StoreError> {
        let day = day_of(e.t);
        if !(layout::MIN_DAY..=layout::MAX_DAY).contains(&day) {
            return Err(StoreError::InvalidRound("event time out of range"));
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
        if !new && !ends_with_newline(&mut f)? {
            line.push(b'\n');
        }
        serde_json::to_writer(&mut line, e)
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

/// Events with `from <= t < to`, oldest first (in the order written for
/// equal times). Lines that do not parse are skipped.
pub fn read_events(data_dir: &Path, from: i64, to: i64) -> Result<Vec<Event>, StoreError> {
    let dir = events_dir(data_dir);
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
            if let Ok(e) = serde_json::from_slice::<Event>(&line) {
                if (from..to).contains(&e.t) {
                    out.push(e);
                }
            }
        }
    }
    // Stable: equal times keep file order.
    out.sort_by_key(|e| e.t);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000;
    const T0: i64 = 1_763_510_400_000; // 2025-11-19T00:00:00Z

    fn raised(t: i64) -> Event {
        let mut e = Event::new(
            t,
            EventKind::AlertRaised,
            "local",
            "slow: median 31ms > 20ms",
        );
        e.target = Some("core-fw".into());
        e.family = Some("v4".into());
        e.series = Some(3);
        e.rule = Some("slow".into());
        e.value = Some(31.0);
        e
    }

    #[test]
    fn events_round_trip_across_days() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = EventLog::open(tmp.path(), 30).unwrap();
        log.append(&raised(T0 + DAY - 1)).unwrap();
        log.append(&raised(T0 + DAY)).unwrap();
        let got = read_events(tmp.path(), T0, T0 + 2 * DAY).unwrap();
        assert_eq!(got, [raised(T0 + DAY - 1), raised(T0 + DAY)]);
        assert!(events_dir(tmp.path()).join("2025-11-19.jsonl").exists());
        assert_eq!(read_events(tmp.path(), T0, T0 + DAY).unwrap().len(), 1);
    }

    #[test]
    fn unknown_kinds_and_torn_lines_are_tolerated() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = EventLog::open(tmp.path(), 30).unwrap();
        log.append(&raised(T0)).unwrap();
        let path = events_dir(tmp.path()).join("2025-11-19.jsonl");
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"t\":5,\"kind\":\"route_changed\",\"vantage\":\"x\"}\n{\"t\":176")
            .unwrap();
        drop(f);
        log.append(&raised(T0 + 1)).unwrap();
        let got = read_events(tmp.path(), 0, T0 + DAY).unwrap();
        let kinds: Vec<_> = got.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                EventKind::Unknown,
                EventKind::AlertRaised,
                EventKind::AlertRaised
            ]
        );
    }

    #[test]
    fn old_days_are_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let mut log = EventLog::open(tmp.path(), 2).unwrap();
        for d in 0..5 {
            log.append(&raised(T0 + d * DAY)).unwrap();
        }
        assert_eq!(list_days(&events_dir(tmp.path())).unwrap().len(), 3);
        assert_eq!(log.expired_files, 2);
    }

    #[test]
    fn empty_fields_are_left_out() {
        let e = Event::new(T0, EventKind::ServerStarted, "local", "started");
        let s = serde_json::to_string(&e).unwrap();
        assert_eq!(
            s,
            "{\"t\":1763510400000,\"kind\":\"server_started\",\"vantage\":\"local\",\"message\":\"started\"}"
        );
    }
}
