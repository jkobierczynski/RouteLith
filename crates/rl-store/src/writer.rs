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
//!
//! The writer is fail-stop: after any I/O error while writing segments or
//! rotating the WAL it refuses further work, and never deletes a WAL file
//! it cannot prove redundant. Reopening the directory runs recovery, which
//! repairs what the failure left behind.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rl_core::TimingBackend;

use crate::index::{self, SeriesKey};
use crate::layout::{self, day_of};
use crate::rollup::{self, RollupPoint, Tier};
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
    /// Days of raw rounds kept; older sealed day segments are deleted whole
    /// once their rollups exist (§6.4: 30 days).
    pub raw_days: i64,
    /// Days of hourly rollups kept (§6.4: 400 days).
    pub r1h_days: i64,
    /// Days of daily rollups kept (§6.4: 10 years).
    pub r1d_days: i64,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            block_rounds: 256,
            seal_grace_ms: 10 * 60 * 1000,
            wal_max_bytes: 64 << 20,
            zstd_level: 3,
            raw_days: 30,
            r1h_days: 400,
            r1d_days: 3653,
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
    /// Sealed days consolidated into the r1h and r1d tiers.
    pub rolled_days: u64,
    /// Files deleted by retention (raw segments and rollup files).
    pub expired_files: u64,
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
    /// Files that could not be fully read. A damaged WAL file is moved to
    /// `quarantine/` once what could be read is in segments; the rounds it
    /// still holds are not in the store.
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
    /// RTT samples in `block`.
    block_samples: usize,
    block_day: Option<i64>,
    /// Newest sealed day.
    sealed_through: Option<i64>,
    /// Last known address and timing backend, filled into rounds that
    /// leave them unset, so every stored round carries them.
    resolved: Option<IpAddr>,
    timing: Option<TimingBackend>,
}

impl Series {
    /// Fill `round`'s unset address and timing from earlier rounds, and
    /// remember the ones it sets.
    fn carry_forward(&mut self, round: &mut StoredRound) {
        match round.resolved {
            Some(a) => self.resolved = Some(a),
            None => round.resolved = self.resolved,
        }
        match round.timing {
            Some(t) => self.timing = Some(t),
            None => round.timing = self.timing,
        }
    }
}

fn damaged_sealed(path: &Path, reason: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt {
        path: path.to_path_buf(),
        reason: format!(
            "sealed segment is damaged ({reason}); the WAL may still hold its later rounds, \
             so the file was left as it is. Move it aside to start without it"
        ),
    }
}

/// Blocks are written early once they hold this many RTT samples, which
/// keeps a block's uncompressed payload far below the reader's limit.
const BLOCK_MAX_SAMPLES: usize = 1 << 20;
/// Largest `block_rounds` accepted.
const MAX_BLOCK_ROUNDS: usize = 4096;

/// Holds the data directory's writer lock: a redb database file, because
/// redb already locks its files exclusively on every platform.
struct DirLock(#[allow(dead_code)] redb::Database);

impl fmt::Debug for DirLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirLock")
    }
}

fn lock_dir(dir: &Path) -> Result<DirLock, StoreError> {
    match redb::Database::create(layout::lock_path(dir)) {
        Ok(db) => Ok(DirLock(db)),
        Err(redb::DatabaseError::DatabaseAlreadyOpen) => Err(StoreError::Locked(dir.to_path_buf())),
        Err(e) => Err(StoreError::Index(format!("writer lock: {e}"))),
    }
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
    /// Directories that gained or lost a name since the last fsync.
    dirty_dirs: BTreeSet<PathBuf>,
    /// WAL files recovery could not fully account for: never deleted, and
    /// moved to `quarantine/` after the recovery checkpoint.
    keep_wal: BTreeSet<u64>,
    /// Set by the first failed write; every later call returns it.
    failed: Option<String>,
    /// The seal cutoff day of the last rollup and retention pass; the pass
    /// runs again when the cutoff moves or a day is sealed.
    rolled_at: Option<i64>,
    stats: WriterStats,
    _lock: DirLock,
}

impl Writer {
    /// Open (creating if needed) a data directory and recover from any crash:
    /// trim torn segment tails, replay the WAL, checkpoint, and seal days
    /// that ended before `now_ms` minus the grace period.
    ///
    /// Only one writer may have a directory open; a second `open` fails
    /// with [`StoreError::Locked`] before touching anything.
    pub fn open(
        dir: &Path,
        opts: WriterOptions,
        now_ms: i64,
    ) -> Result<(Self, Recovery), StoreError> {
        if !(1..=MAX_BLOCK_ROUNDS).contains(&opts.block_rounds) {
            return Err(StoreError::InvalidOptions("block_rounds must be 1 to 4096"));
        }
        if opts.raw_days < 1 || opts.r1h_days < 1 || opts.r1d_days < 1 {
            return Err(StoreError::InvalidOptions(
                "retention must be at least one day per tier",
            ));
        }
        // Every directory `create_dir_all` is about to make.
        let mut created = Vec::new();
        let mut p = dir.to_path_buf();
        while !p.as_os_str().is_empty() && !p.try_exists()? {
            created.push(p.clone());
            match p.parent() {
                Some(parent) => p = parent.to_path_buf(),
                None => break,
            }
        }
        std::fs::create_dir_all(dir)?;
        let lock = lock_dir(dir)?;
        std::fs::create_dir_all(layout::wal_dir(dir))?;
        std::fs::create_dir_all(dir.join("series"))?;
        // Make the names durable before any WAL sync is acknowledged: the
        // entries in `dir`, then the entry of `dir` and of each ancestor in
        // its parent. Existing ancestors too, as an earlier start may have
        // created them and stopped before syncing.
        layout::sync_dir(dir)?;
        let mut p = dir.to_path_buf();
        loop {
            if let Err(e) = layout::sync_dir(&layout::parent_or_dot(&p)) {
                // The data directory's own entry must sync, on a retry too.
                // Above it, only a parent this process may not open (a
                // system directory) is passed over, unless this start
                // created the entry.
                if p == dir
                    || created.contains(&p)
                    || e.kind() != std::io::ErrorKind::PermissionDenied
                {
                    return Err(e.into());
                }
            }
            match p.parent() {
                Some(q) if !q.as_os_str().is_empty() => p = q.to_path_buf(),
                _ => break,
            }
        }
        let mut rec = Recovery::default();
        let mut series: BTreeMap<u64, Series> = BTreeMap::new();
        let mut dirty = BTreeSet::new();
        let mut dirty_dirs = BTreeSet::new();

        for id in layout::list_series_dirs(dir)? {
            let s = series.entry(id).or_default();
            let mut open_days = Vec::new();
            for seg in layout::list_segments(dir, id)? {
                let bytes = std::fs::read(&seg.path)?;
                let mut scan = match segment::scan(&bytes) {
                    Ok(scan) => scan,
                    // A crash right after creating the file, before its header was written.
                    Err(_) if !seg.sealed && bytes.len() < segment::HEADER_LEN => {
                        std::fs::remove_file(&seg.path)?;
                        continue;
                    }
                    // A damaged sealed day must not be treated as complete
                    // (that would drop its WAL copies as late): stop, and
                    // leave this file as it is for the operator (segments handled
                    // before it may already have been repaired).
                    Err(e) if seg.sealed => return Err(damaged_sealed(&seg.path, e)),
                    // A damaged open segment: set it aside so the day can
                    // start again (from the WAL rounds it may still have),
                    // instead of failing to create a file of the same name.
                    Err(e) => {
                        let name = format!(
                            "series-{id}-{}",
                            seg.path
                                .file_name()
                                .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
                        );
                        let to = quarantine(dir, &seg.path, &name)?;
                        layout::sync_dir(&layout::raw_dir(dir, id))?;
                        rec.problems.push(format!(
                            "{}: {e}; moved to {}, its rounds are not in the store",
                            seg.path.display(),
                            to.display()
                        ));
                        continue;
                    }
                };
                // A file from another series or day must not move this
                // series' cutoffs (its WAL rounds would be dropped as late),
                // and readers refuse it too: stop, leaving the file as it is.
                if scan.series != id || scan.day != seg.day {
                    return Err(StoreError::Corrupt {
                        path: seg.path.clone(),
                        reason: format!(
                            "segment header names series {} day {}, not series {id} day {}; \
                             the file was left as it is. Move it aside to start without it",
                            scan.series,
                            layout::date(scan.day),
                            layout::date(seg.day)
                        ),
                    });
                }
                // Only blocks that decode, in order and inside the file's
                // day, may move the replay cutoff: keep the blocks before
                // the first one that does not (a sealed file with such a
                // block is refused below).
                let mut last_round: Option<StoredRound> = None;
                for i in 0..scan.blocks.len() {
                    let off = scan.blocks[i].0;
                    let decoded = match codec::read_frame(&bytes[off..]) {
                        codec::Frame::Ok(body, _) => codec::decode_block(body),
                        _ => None,
                    };
                    let mut prev = last_round.as_ref().map_or(i64::MIN, |r| r.ts_ms);
                    let valid = decoded.filter(|rounds| {
                        rounds.iter().all(|r| {
                            let ok = r.ts_ms > prev && day_of(r.ts_ms) == seg.day;
                            prev = r.ts_ms;
                            ok
                        })
                    });
                    match valid {
                        Some(rounds) => last_round = rounds.last().cloned().or(last_round),
                        None => {
                            scan.blocks.truncate(i);
                            scan.valid_len = off as u64;
                            scan.tail = Tail::Corrupt;
                            break;
                        }
                    }
                }
                if scan.tail != Tail::Clean {
                    if seg.sealed {
                        return Err(damaged_sealed(
                            &seg.path,
                            format!("bad block after offset {}", scan.valid_len),
                        ));
                    } else {
                        // Damage, not a torn write: the cut may drop intact
                        // blocks whose WAL is already gone, so keep a copy of
                        // the whole file for the operator first.
                        if scan.tail == Tail::Corrupt {
                            let copy = seg.path.with_extension("damaged");
                            // Written and synced through one handle: Windows
                            // cannot flush a file opened only for reading.
                            let mut f = std::fs::File::create(&copy)?;
                            std::io::Write::write_all(&mut f, &bytes)?;
                            f.sync_all()?;
                            drop(f);
                            let name = format!(
                                "series-{id}-{}",
                                seg.path
                                    .file_name()
                                    .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
                            );
                            let to = quarantine(dir, &copy, &name)?;
                            rec.problems.push(format!(
                                "{}: bad block after offset {}; cut there, and the whole file \
                                 was copied to {} (rounds after the cut that the WAL no \
                                 longer holds are only in that copy)",
                                seg.path.display(),
                                scan.valid_len,
                                to.display()
                            ));
                        }
                        segment::truncate(&seg.path, scan.valid_len)?;
                        rec.truncated_segments += 1;
                    }
                }
                s.last_ts = s.last_ts.max(scan.last_ts());
                if let Some(r) = last_round.filter(|r| Some(r.ts_ms) == s.last_ts) {
                    s.resolved = r.resolved.or(s.resolved);
                    // The last round's own timing, unknown included: an
                    // unknown backend must not be replaced by an older one.
                    s.timing = r.timing;
                }
                // The names of this file and its directories may be only in
                // the page cache after a kill (a seal renamed just before
                // it, say): sync them before any WAL is retired.
                let raw = layout::raw_dir(dir, id);
                if let Some(series_dir) = raw.parent() {
                    dirty_dirs.insert(series_dir.to_path_buf());
                }
                dirty_dirs.insert(raw);
                dirty_dirs.insert(dir.join("series"));
                if seg.sealed {
                    s.sealed_through = s.sealed_through.max(Some(seg.day));
                } else {
                    open_days.push(seg.day);
                    // Likewise its blocks.
                    dirty.insert(seg.path.clone());
                }
            }
            // Normally at most one open segment; older ones are complete.
            open_days.sort_unstable();
            s.open_day = open_days.pop();
            for day in open_days {
                dirty.remove(&layout::segment_path(dir, id, day, false));
                seal_file(dir, id, day)?;
                s.sealed_through = s.sealed_through.max(Some(day));
            }
        }

        let seqs = layout::list_wal(dir)?;
        let next_seq = next_wal_seq(dir, seqs.last().copied())?;
        let wal = WalWriter::create(layout::wal_path(dir, next_seq), next_seq)?;
        layout::sync_dir(&layout::wal_dir(dir))?;
        let mut w = Self {
            dir: dir.to_path_buf(),
            opts,
            wal,
            series,
            dirty,
            dirty_dirs,
            keep_wal: BTreeSet::new(),
            failed: None,
            rolled_at: None,
            stats: WriterStats::default(),
            _lock: lock,
        };

        for seq in seqs {
            let path = layout::wal_path(dir, seq);
            let bytes = std::fs::read(&path)?;
            rec.wal_files += 1;
            let (records, tail) = match wal::read(&bytes) {
                Ok(r) => r,
                // Header never fully written: the file holds no rounds.
                Err(_) if bytes.len() < wal::HEADER_LEN => continue,
                Err(e) => {
                    rec.problems.push(format!("{}: {e}", path.display()));
                    w.keep_wal.insert(seq);
                    continue;
                }
            };
            match tail {
                Tail::Clean => {}
                Tail::Torn => rec.torn_wal += 1,
                // Records after a bad checksum cannot be read: keep the file.
                Tail::Corrupt => {
                    rec.torn_wal += 1;
                    rec.problems.push(format!(
                        "{}: bad record; the rounds after it were not replayed",
                        path.display()
                    ));
                    w.keep_wal.insert(seq);
                }
            }
            for (id, round) in records {
                match w.ingest(id, round, false)? {
                    Appended::Stored => rec.replayed += 1,
                    Appended::Late => rec.skipped += 1,
                }
            }
        }
        w.stats = WriterStats::default();
        w.guard(|w| w.checkpoint())?;
        // What could be read is now durable in segments: move the damaged
        // files out of the live WAL set, so readers are not blocked by them.
        for (seq, to) in w.guard(|w| w.quarantine_kept_wal())? {
            rec.problems.push(format!(
                "{}: moved to {}",
                layout::wal_path(dir, seq).display(),
                to.display()
            ));
        }
        w.maintain(now_ms)?;
        Ok((w, rec))
    }

    /// Look up or assign series ids in `meta.redb`.
    /// Refused once the writer has stopped, like every other write; a
    /// refused key does not stop it.
    pub fn register(&mut self, keys: &[SeriesKey]) -> Result<Vec<u64>, StoreError> {
        if let Some(msg) = &self.failed {
            return Err(StoreError::Stopped(msg.clone()));
        }
        index::register(&self.dir, keys)
    }

    /// Record each series' step (round interval) in milliseconds, so
    /// readers know the cadence even when rounds are sparse (§21.3 E5).
    pub fn set_steps(&mut self, steps: &[(u64, u64)]) -> Result<(), StoreError> {
        if let Some(msg) = &self.failed {
            return Err(StoreError::Stopped(msg.clone()));
        }
        index::set_steps(&self.dir, steps)
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
        self.guard(|w| w.ingest(series, round, true))
    }

    /// `fsync` the WAL. Call about once a second (§6.2); a crash loses at
    /// most the rounds appended since the last call.
    pub fn sync(&mut self) -> Result<(), StoreError> {
        self.guard(|w| Ok(w.wal.sync()?))
    }

    /// Seal days that ended before `now_ms` minus the grace period, and
    /// checkpoint when anything was sealed or the WAL is large.
    pub fn maintain(&mut self, now_ms: i64) -> Result<(), StoreError> {
        self.guard(|w| w.maintain_inner(now_ms))
    }

    /// Checkpoint and close. Without this, the next open replays the WAL.
    pub fn close(mut self) -> Result<(), StoreError> {
        self.guard(|w| w.checkpoint())
    }

    /// Run `f` unless an earlier write failed; a failure (other than an
    /// invalid round) stops the writer.
    fn guard<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        if let Some(msg) = &self.failed {
            return Err(StoreError::Stopped(msg.clone()));
        }
        let r = f(self);
        if let Err(e) = &r {
            if !matches!(e, StoreError::InvalidRound(_)) {
                self.failed = Some(e.to_string());
            }
        }
        r
    }

    fn maintain_inner(&mut self, now_ms: i64) -> Result<(), StoreError> {
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
        if !stale.is_empty() || self.rolled_at != Some(cutoff) {
            self.roll_up(cutoff)?;
            self.rolled_at = Some(cutoff);
        }
        Ok(())
    }

    /// Build the r1h and r1d points of every sealed day that has none yet,
    /// then apply retention. `today` is the seal cutoff day: days before it
    /// are sealed or will not change.
    fn roll_up(&mut self, today: i64) -> Result<(), StoreError> {
        for id in layout::list_series_dirs(&self.dir)? {
            let last = rollup::last_rolled_day(&self.dir, id)?;
            for seg in layout::list_segments(&self.dir, id)? {
                if !seg.sealed || last.is_some_and(|l| seg.day <= l) {
                    continue;
                }
                let bytes = std::fs::read(&seg.path)?;
                let scan = segment::scan(&bytes).map_err(|r| damaged_sealed(&seg.path, r))?;
                if scan.tail != Tail::Clean || scan.series != id || scan.day != seg.day {
                    return Err(damaged_sealed(&seg.path, "bad block or header"));
                }
                let rounds = segment::read_range(&bytes, &scan, i64::MIN, i64::MAX)
                    .map_err(|r| damaged_sealed(&seg.path, r))?;
                // r1h first: an r1d point marks the day as fully rolled up.
                for tier in [Tier::R1h, Tier::R1d] {
                    let points = RollupPoint::build(&rounds, tier.width_ms());
                    rollup::append_day(&self.dir, id, tier, seg.day, &points)?;
                }
                self.stats.rolled_days += 1;
            }
            // Retention: whole files only (§6.4). Every sealed raw day was
            // rolled up above before any is deleted.
            let raw_before = today - self.opts.raw_days;
            let mut removed = false;
            for seg in layout::list_segments(&self.dir, id)? {
                if seg.sealed && seg.day < raw_before {
                    std::fs::remove_file(&seg.path)?;
                    self.stats.expired_files += 1;
                    removed = true;
                }
            }
            if removed {
                layout::sync_dir(&layout::raw_dir(&self.dir, id))?;
            }
            for (tier, days) in [
                (Tier::R1h, self.opts.r1h_days),
                (Tier::R1d, self.opts.r1d_days),
            ] {
                self.stats.expired_files +=
                    rollup::expire(&self.dir, id, tier, today - days)? as u64;
            }
        }
        Ok(())
    }

    fn ingest(
        &mut self,
        id: u64,
        mut round: StoredRound,
        log: bool,
    ) -> Result<Appended, StoreError> {
        let day = day_of(round.ts_ms);
        let s = self.series.entry(id).or_default();
        let late = s.last_ts.is_some_and(|t| round.ts_ms <= t)
            || s.sealed_through.is_some_and(|d| day <= d);
        if late {
            self.stats.late += 1;
            return Ok(Appended::Late);
        }
        s.carry_forward(&mut round);
        // Write out the previous day's block before logging this round, so
        // a failure leaves this round neither in the WAL nor in a block.
        if s.block_day.is_some_and(|d| d != day) {
            self.flush_block(id)?;
        }
        if log {
            self.wal.append(id, &round)?;
        }
        let s = self.series.get_mut(&id).expect("entry created above");
        s.last_ts = Some(round.ts_ms);
        s.block_day = Some(day);
        s.block_samples += round.rtts_us.len();
        s.block.push(round);
        let full = s.block.len() >= self.opts.block_rounds || s.block_samples >= BLOCK_MAX_SAMPLES;
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
        s.block_samples = 0;
        s.block_day = None;
        self.dirty.insert(path);
        self.stats.blocks += 1;
        Ok(())
    }

    /// Make a day's open segment immutable. Its pending block must already
    /// be flushed.
    fn seal(&mut self, id: u64, day: i64) -> Result<(), StoreError> {
        seal_file(&self.dir, id, day)?;
        // Synced by `seal_file`; tracked until then.
        self.dirty
            .remove(&layout::segment_path(&self.dir, id, day, false));
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
        // Each entry stays tracked until its own barrier succeeds.
        while let Some(path) = self.dirty.first().cloned() {
            segment::sync(&path)?;
            self.dirty.remove(&path);
        }
        // Deepest directories first.
        while let Some(dir) = self.dirty_dirs.last().cloned() {
            layout::sync_dir(&dir)?;
            self.dirty_dirs.remove(&dir);
        }
        // The new WAL is used only once its name is durable.
        let next = next_wal_seq(&self.dir, Some(self.wal.seq()))?;
        let path = layout::wal_path(&self.dir, next);
        let wal = WalWriter::create(path.clone(), next)?;
        if let Err(e) = layout::sync_dir(&layout::wal_dir(&self.dir)) {
            drop(wal);
            let _ = std::fs::remove_file(&path);
            return Err(e.into());
        }
        self.wal = wal;
        for seq in layout::list_wal(&self.dir)? {
            if seq < next && !self.keep_wal.contains(&seq) {
                std::fs::remove_file(layout::wal_path(&self.dir, seq))?;
            }
        }
        layout::sync_dir(&layout::wal_dir(&self.dir))?;
        self.stats.checkpoints += 1;
        Ok(())
    }
}

impl Writer {
    /// Move the WAL files recovery could not fully read into
    /// `quarantine/`. Called right after the recovery checkpoint.
    fn quarantine_kept_wal(&mut self) -> Result<Vec<(u64, PathBuf)>, StoreError> {
        let mut moved = Vec::new();
        while let Some(seq) = self.keep_wal.first().copied() {
            let to = quarantine(
                &self.dir,
                &layout::wal_path(&self.dir, seq),
                &format!("{seq:08}.wal"),
            )?;
            layout::sync_dir(&layout::wal_dir(&self.dir))?;
            self.keep_wal.remove(&seq);
            moved.push((seq, to));
        }
        Ok(moved)
    }
}

/// Move a damaged file into `quarantine/` as `name` (with a numeric suffix
/// if taken), and make its new name durable. The caller syncs the
/// directory it came from.
fn quarantine(dir: &Path, from: &Path, name: &str) -> Result<PathBuf, StoreError> {
    let q = layout::quarantine_dir(dir);
    if !q.try_exists()? {
        std::fs::create_dir(&q)?;
    }
    // Every call: an earlier one may have created `quarantine/` and stopped
    // before making its entry durable.
    layout::sync_dir(dir)?;
    let mut to = q.join(name);
    let mut n = 1;
    while to.try_exists()? {
        to = q.join(format!("{name}.{n}"));
        n += 1;
    }
    std::fs::rename(from, &to)?;
    layout::sync_dir(&q)?;
    Ok(to)
}

/// Sequence number for a new WAL file after `last`. An exhausted sequence
/// is an error that leaves every WAL file as it is.
fn next_wal_seq(dir: &Path, last: Option<u64>) -> Result<u64, StoreError> {
    match last {
        None => Ok(1),
        Some(s) => s.checked_add(1).ok_or_else(|| StoreError::Corrupt {
            path: layout::wal_path(dir, s),
            reason: "WAL sequence numbers are exhausted; cannot create the next WAL file".into(),
        }),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_undecodable_block_before_a_good_one_does_not_move_the_cutoff() {
        use crate::{ErrorCounts, Reader, SeriesKey};
        let dir = tempfile::tempdir().unwrap();
        let day_ms = 86_400_000;
        let base = 20_000 * day_ms;
        let opts = WriterOptions {
            block_rounds: 2,
            ..WriterOptions::default()
        };
        let round = |i: i64| StoredRound {
            ts_ms: base + i * 60_000,
            sent: 3,
            rtts_us: vec![1000, 1100],
            errors: ErrorCounts::default(),
            resolved: None,
            timing: None,
            flags: 0,
        };
        let (mut w, _) = Writer::open(dir.path(), opts, base).unwrap();
        let id = w.register(&[SeriesKey::new("v", "t", "v4")]).unwrap()[0];
        for i in 0..6 {
            w.append(id, round(i)).unwrap();
        }
        w.sync().unwrap();
        // A crash: the WAL still holds every round, the open segment has
        // three blocks.
        drop(w);
        let path = layout::segment_path(dir.path(), id, base / day_ms, false);
        let mut bytes = std::fs::read(&path).unwrap();
        let scan = segment::scan(&bytes).unwrap();
        assert_eq!(scan.blocks.len(), 3);
        // Damage the first block's payload behind a valid checksum.
        let off = scan.blocks[0].0;
        let len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        let body = off + 8;
        for b in &mut bytes[body + 18..body + len] {
            *b = 0xA5;
        }
        let crc = crc32c::crc32c(&bytes[body..body + len]);
        bytes[off + 4..off + 8].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();

        let (w, rec) = Writer::open(dir.path(), opts, base).unwrap();
        assert_eq!(rec.truncated_segments, 1);
        assert!(
            rec.problems.iter().any(|p| p.contains("copied")),
            "{:?}",
            rec.problems
        );
        // The intact later blocks are kept in the copy.
        let copy = std::fs::read_dir(layout::quarantine_dir(dir.path()))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(std::fs::read(copy).unwrap(), bytes);
        w.close().unwrap();
        let got = Reader::open(dir.path())
            .unwrap()
            .read(id, base, base + day_ms)
            .unwrap();
        let want: Vec<StoredRound> = (0..6).map(round).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn an_exhausted_wal_sequence_is_an_error() {
        assert_eq!(next_wal_seq(Path::new("d"), None).unwrap(), 1);
        assert_eq!(next_wal_seq(Path::new("d"), Some(7)).unwrap(), 8);
        assert!(matches!(
            next_wal_seq(Path::new("d"), Some(u64::MAX)),
            Err(StoreError::Corrupt { .. })
        ));
    }
}
