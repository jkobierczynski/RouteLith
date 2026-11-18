//! The single writer (architecture doc §6.2, §6.5, §16).
//!
//! Write path: round → WAL (fsync batched by the caller, normally every
//! second) → in-memory block → open day segment when the block is full or at
//! a checkpoint → sealed at the UTC day boundary.
//!
//! A *checkpoint* writes every pending block to its open segment, fsyncs the
//! segments, starts a new WAL file and deletes the older ones. It runs after
//! day sealing, when the WAL grows past a limit, at shutdown and right after
//! recovery. A crash at any point leaves either the WAL or the segments (or
//! both) holding every synced round; replay skips rounds a segment already
//! has, because rounds of one series only move forward in time.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::index::{self, SeriesKey};
use crate::layout::{self, day_of};
use crate::round::StoredRound;
use crate::segment::{self, Tail};
use crate::wal::{self, WalWriter};
use crate::{StoreError, codec};

/// Tuning knobs; the defaults follow the architecture doc.
#[derive(Debug, Clone, Copy)]
pub struct WriterOptions {
    /// Rounds per block (§6.3).
    pub block_rounds: usize,
    /// How long after UTC midnight a day's segments stay open for late rounds.
    pub seal_grace_ms: i64,
    /// Checkpoint when the WAL grows past this many bytes.
    pub wal_max_bytes: u64,
    pub zstd_level: i32,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            block_rounds: 256,
            seal_grace_ms: 10 * 60 * 1000,
            wal_max_bytes: 64 << 20,
            zstd_level: 3,
        }
    }
}

/// Counters since the writer was opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterStats {
    pub appended: u64,
    /// Rounds dropped because they were not newer than the series' last
    /// round, or belonged to a day already sealed.
    pub late: u64,
    pub blocks: u64,
    pub sealed: u64,
    pub checkpoints: u64,
}

/// What [`Writer::open`] found and repaired.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Recovery {
    pub wal_files: usize,
    /// WAL rounds not yet in a segment, now restored.
    pub replayed: u64,
    /// WAL rounds a segment already had.
    pub skipped: u64,
    /// WAL files that ended in a torn or corrupt record.
    pub torn_wal: usize,
    /// Open segments cut back to their last valid block.
    pub truncated_segments: usize,
    /// Files that could not be read; they are left in place.
    pub problems: Vec<String>,
}

/// Outcome of [`Writer::append`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    Stored,
    /// Not newer than the series' last round, or for a sealed day: dropped.
    Late,
}

#[derive(Debug, Default)]
struct Series {
    /// Day of the open segment on disk, if any.
    open_day: Option<i64>,
    /// Newest round accepted.
    last_ts: Option<i64>,
    /// Rounds not yet written to a segment, all from `block_day`.
    block: Vec<StoredRound>,
    block_day: Option<i64>,
    /// Newest sealed day.
    sealed_through: Option<i64>,
}

/// The only writer of a data directory.
#[derive(Debug)]
pub struct Writer {
    dir: PathBuf,
    opts: WriterOptions,
    wal: WalWriter,
    series: BTreeMap<u64, Series>,
    /// Segment files written since the last fsync.
    dirty: BTreeSet<PathBuf>,
    /// Directories that gained a file since the last fsync.
    dirty_dirs: BTreeSet<PathBuf>,
    stats: WriterStats,
}

impl Writer {
    /// Open (creating if needed) a data directory and recover from any crash:
    /// trim torn segment tails, replay the WAL, checkpoint, and seal days
    /// that ended before `now_ms` minus the grace period.
    pub fn open(
        dir: &Path,
        opts: WriterOptions,
        now_ms: i64,
    ) -> Result<(Self, Recovery), StoreError> {
        std::fs::create_dir_all(layout::wal_dir(dir))?;
        std::fs::create_dir_all(dir.join("series"))?;
        let mut rec = Recovery::default();
        let mut series: BTreeMap<u64, Series> = BTreeMap::new();

        for id in layout::list_series_dirs(dir)? {
            let s = series.entry(id).or_default();
            let mut open_days = Vec::new();
            for seg in layout::list_segments(dir, id)? {
                let bytes = std::fs::read(&seg.path)?;
                let scan = match segment::scan(&bytes) {
                    Ok(scan) => scan,
                    // A crash right after creating the file, before its header was written.
                    Err(_) if !seg.sealed && bytes.len() < segment::HEADER_LEN => {
                        std::fs::remove_file(&seg.path)?;
                        continue;
                    }
                    Err(e) => {
                        rec.problems.push(format!("{}: {e}", seg.path.display()));
                        continue;
                    }
                };
                if scan.tail != Tail::Clean {
                    if seg.sealed {
                        rec.problems.push(format!(
                            "{}: sealed segment has a bad block after offset {}",
                            seg.path.display(),
                            scan.valid_len
                        ));
                    } else {
                        segment::truncate(&seg.path, scan.valid_len)?;
                        rec.truncated_segments += 1;
                    }
                }
                s.last_ts = s.last_ts.max(scan.last_ts());
                if seg.sealed {
                    s.sealed_through = s.sealed_through.max(Some(seg.day));
                } else {
                    open_days.push(seg.day);
                }
            }
            // Normally at most one open segment; older ones are complete.
            open_days.sort_unstable();
            s.open_day = open_days.pop();
            for day in open_days {
                seal_file(dir, id, day)?;
                s.sealed_through = s.sealed_through.max(Some(day));
            }
        }

        let seqs = layout::list_wal(dir)?;
        let next_seq = seqs.last().map_or(1, |s| s + 1);
        let wal = WalWriter::create(layout::wal_path(dir, next_seq), next_seq)?;
        layout::sync_dir(&layout::wal_dir(dir))?;
        let mut w = Self {
            dir: dir.to_path_buf(),
            opts,
            wal,
            series,
            dirty: BTreeSet::new(),
            dirty_dirs: BTreeSet::new(),
            stats: WriterStats::default(),
        };

        for seq in seqs {
            let path = layout::wal_path(dir, seq);
            let bytes = std::fs::read(&path)?;
            rec.wal_files += 1;
            let (records, tail) = match wal::read(&bytes) {
                Ok(r) => r,
                // Header never fully written: the file holds no rounds.
                Err(_) if bytes.len() < 20 => continue,
                Err(e) => {
                    rec.problems.push(format!("{}: {e}", path.display()));
                    continue;
                }
            };
            if tail != Tail::Clean {
                rec.torn_wal += 1;
            }
            for (id, round) in records {
                match w.ingest(id, round, false)? {
                    Appended::Stored => rec.replayed += 1,
                    Appended::Late => rec.skipped += 1,
                }
            }
        }
        w.stats = WriterStats::default();
        w.checkpoint()?;
        w.maintain(now_ms)?;
        Ok((w, rec))
    }

    /// Look up or assign series ids in `meta.redb`.
    pub fn register(&mut self, keys: &[SeriesKey]) -> Result<Vec<u64>, StoreError> {
        index::register(&self.dir, keys)
    }

    pub fn stats(&self) -> WriterStats {
        self.stats
    }

    /// Bytes in the current WAL file.
    pub fn wal_bytes(&self) -> u64 {
        self.wal.bytes()
    }

    /// Store one round. Durable after the next [`sync`](Self::sync).
    pub fn append(&mut self, series: u64, round: StoredRound) -> Result<Appended, StoreError> {
        round.check().map_err(StoreError::InvalidRound)?;
        self.ingest(series, round, true)
    }

    /// `fsync` the WAL. Call about once a second (§6.2); a crash loses at
    /// most the rounds appended since the last call.
    pub fn sync(&mut self) -> Result<(), StoreError> {
        Ok(self.wal.sync()?)
    }

    /// Seal days that ended before `now_ms` minus the grace period, and
    /// checkpoint when anything was sealed or the WAL is large.
    pub fn maintain(&mut self, now_ms: i64) -> Result<(), StoreError> {
        let cutoff = day_of(now_ms.saturating_sub(self.opts.seal_grace_ms));
        let stale: Vec<u64> = self
            .series
            .iter()
            .filter(|(_, s)| {
                s.block_day.is_some_and(|d| d < cutoff) || s.open_day.is_some_and(|d| d < cutoff)
            })
            .map(|(&id, _)| id)
            .collect();
        for &id in &stale {
            if self.series[&id].block_day.is_some_and(|d| d < cutoff) {
                self.flush_block(id)?;
            }
            if let Some(day) = self.series[&id].open_day.filter(|&d| d < cutoff) {
                self.seal(id, day)?;
            }
        }
        if !stale.is_empty() || self.wal.bytes() > self.opts.wal_max_bytes {
            self.checkpoint()?;
        }
        Ok(())
    }

    /// Checkpoint and close. Without this, the next open replays the WAL.
    pub fn close(mut self) -> Result<(), StoreError> {
        self.checkpoint()
    }

    fn ingest(&mut self, id: u64, round: StoredRound, log: bool) -> Result<Appended, StoreError> {
        let day = day_of(round.ts_ms);
        let s = self.series.entry(id).or_default();
        let late = s.last_ts.is_some_and(|t| round.ts_ms <= t)
            || s.sealed_through.is_some_and(|d| day <= d);
        if late {
            self.stats.late += 1;
            return Ok(Appended::Late);
        }
        if log {
            self.wal.append(id, &round)?;
        }
        if self.series[&id].block_day.is_some_and(|d| d != day) {
            self.flush_block(id)?;
        }
        let s = self.series.get_mut(&id).expect("entry created above");
        s.last_ts = Some(round.ts_ms);
        s.block_day = Some(day);
        s.block.push(round);
        let full = s.block.len() >= self.opts.block_rounds;
        self.stats.appended += 1;
        if full {
            self.flush_block(id)?;
        }
        Ok(Appended::Stored)
    }

    /// Write the series' pending block to its day's open segment, sealing
    /// an older open segment first.
    fn flush_block(&mut self, id: u64) -> Result<(), StoreError> {
        let s = self.series.get_mut(&id).expect("known series");
        let Some(day) = s.block_day else {
            return Ok(());
        };
        if s.block.is_empty() {
            s.block_day = None;
            return Ok(());
        }
        if let Some(old) = s.open_day.filter(|&d| d < day) {
            self.seal(id, old)?;
        }
        let path = layout::segment_path(&self.dir, id, day, false);
        let s = self.series.get_mut(&id).expect("known series");
        if s.open_day != Some(day) {
            segment::create(&path, id, day)?;
            s.open_day = Some(day);
            if let Some(parent) = path.parent() {
                self.dirty_dirs.insert(parent.to_path_buf());
                if let Some(series_dir) = parent.parent() {
                    self.dirty_dirs.insert(series_dir.to_path_buf());
                }
            }
            self.dirty_dirs.insert(self.dir.join("series"));
        }
        let body = codec::encode_block(&s.block, self.opts.zstd_level);
        segment::append_block(&path, &body)?;
        s.block.clear();
        s.block_day = None;
        self.dirty.insert(path);
        self.stats.blocks += 1;
        Ok(())
    }

    /// Make a day's open segment immutable. Its pending block must already
    /// be flushed.
    fn seal(&mut self, id: u64, day: i64) -> Result<(), StoreError> {
        let open = layout::segment_path(&self.dir, id, day, false);
        self.dirty.remove(&open);
        seal_file(&self.dir, id, day)?;
        let s = self.series.get_mut(&id).expect("known series");
        s.open_day = None;
        s.sealed_through = s.sealed_through.max(Some(day));
        self.stats.sealed += 1;
        Ok(())
    }

    fn checkpoint(&mut self) -> Result<(), StoreError> {
        let ids: Vec<u64> = self.series.keys().copied().collect();
        for id in ids {
            self.flush_block(id)?;
        }
        for path in std::mem::take(&mut self.dirty) {
            segment::sync(&path)?;
        }
        for dir in std::mem::take(&mut self.dirty_dirs).into_iter().rev() {
            layout::sync_dir(&dir)?;
        }
        let old_seq = self.wal.seq();
        let next = old_seq + 1;
        self.wal = WalWriter::create(layout::wal_path(&self.dir, next), next)?;
        layout::sync_dir(&layout::wal_dir(&self.dir))?;
        for seq in layout::list_wal(&self.dir)? {
            if seq < next {
                std::fs::remove_file(layout::wal_path(&self.dir, seq))?;
            }
        }
        layout::sync_dir(&layout::wal_dir(&self.dir))?;
        self.stats.checkpoints += 1;
        Ok(())
    }
}

/// fsync an open segment and rename it to `.seg`.
fn seal_file(dir: &Path, id: u64, day: i64) -> Result<(), StoreError> {
    let open = layout::segment_path(dir, id, day, false);
    let sealed = layout::segment_path(dir, id, day, true);
    segment::sync(&open)?;
    std::fs::rename(&open, &sealed)?;
    layout::sync_dir(&layout::raw_dir(dir, id))?;
    Ok(())
}
