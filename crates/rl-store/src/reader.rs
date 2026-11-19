//! Reading a data directory, also while a server writes to it.
//!
//! Sealed segments never change. An open segment or WAL file may end in a
//! half-written frame; readers stop there, as recovery would.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::index::{self, SeriesKey};
use crate::layout::{self, day_of};
use crate::rollup::{self, RollupPoint, Tier};
use crate::round::StoredRound;
use crate::segment::{self, Tail};
use crate::{StoreError, codec, wal};

/// Read access to a data directory.
#[derive(Debug)]
pub struct Reader {
    dir: PathBuf,
    series: Vec<(SeriesKey, u64)>,
    /// Recorded step per series, milliseconds.
    steps: BTreeMap<u64, u64>,
}

/// The resolution a range was read at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// One point per stored round.
    Raw,
    /// One point per hour or day.
    Rollup(Tier),
}

/// What [`Reader::read_graph`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphRounds {
    pub resolution: Resolution,
    /// For rollups, one synthetic round per point, each scaled on its own:
    /// their counts keep each point's loss ratio, not the range's totals.
    pub rounds: Vec<StoredRound>,
    /// Pings sent and replies received over the whole range, unscaled.
    pub sent: u64,
    pub received: u64,
}

/// Step assumed for a series with none recorded (the config default).
const DEFAULT_STEP_MS: u64 = 300_000;
/// Attempts at a read that retention or a roll-up changes under it.
const ATTEMPTS: usize = 5;

/// Result of [`Reader::verify`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub segments: usize,
    pub blocks: usize,
    pub rounds: u64,
    /// Open segments ending in a half-written block (normal right after a
    /// crash, repaired at the next start).
    pub torn_open: usize,
    /// Checksum or decoding failures.
    pub problems: Vec<String>,
}

/// Run a read again while retention or a roll-up changes the files under
/// it (each change is quick, and happens about once a day).
fn retry<T>(mut f: impl FnMut() -> Result<T, StoreError>) -> Result<T, StoreError> {
    let mut n = 0;
    loop {
        match f() {
            Err(StoreError::Expired(_)) if n + 1 < ATTEMPTS => n += 1,
            r => return r,
        }
    }
}

impl Reader {
    /// Open a data directory and load its series index.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            dir: dir.to_path_buf(),
            series: index::load(dir)?,
            steps: index::load_steps(dir)?,
        })
    }

    /// Every registered series, sorted by key.
    pub fn series(&self) -> &[(SeriesKey, u64)] {
        &self.series
    }

    /// Series of a target, across vantages and families.
    pub fn find(&self, target: &str) -> Vec<(&SeriesKey, u64)> {
        self.series
            .iter()
            .filter(|(k, _)| k.target == target)
            .map(|(k, id)| (k, *id))
            .collect()
    }

    /// The step (round interval) recorded for a series, in milliseconds.
    /// `None` for a series written before steps were recorded and not
    /// measured since.
    pub fn step_ms(&self, series: u64) -> Option<u64> {
        self.steps.get(&series).copied()
    }

    /// Points of one rollup tier with `from_ms <= ts <= to_ms`, oldest
    /// first. Days not rolled up yet (today, and days awaiting their seal)
    /// are consolidated from the raw rounds on the fly, so the range has no
    /// hole at its recent end.
    pub fn read_tier(
        &self,
        series: u64,
        tier: Tier,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<RollupPoint>, StoreError> {
        retry(|| self.read_tier_once(series, tier, from_ms, to_ms))
    }

    fn read_tier_once(
        &self,
        series: u64,
        tier: Tier,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<RollupPoint>, StoreError> {
        // The points and the boundary of what they cover must be read
        // together: a day rolled up in between would be in neither.
        let before = rollup::last_rolled_day(&self.dir, series)?;
        let mut out = rollup::read(&self.dir, series, tier, from_ms, to_ms)?;
        let last = rollup::last_rolled_day(&self.dir, series)?;
        if last != before {
            return Err(StoreError::Expired(rollup::tier_dir(
                &self.dir, series, tier,
            )));
        }
        let rolled_until = last.map_or(i64::MIN, |d| (d + 1).saturating_mul(layout::DAY_MS));
        let raw_from = from_ms.max(rolled_until);
        if raw_from <= to_ms {
            // Start at a bucket boundary, so the first bucket is whole.
            let start = raw_from.saturating_sub(raw_from.rem_euclid(tier.width_ms()));
            let rounds = self.read(series, start, to_ms)?;
            // A day rolled up and expired from raw during that read is in
            // neither part.
            if rollup::last_rolled_day(&self.dir, series)? != last {
                return Err(StoreError::Expired(layout::raw_dir(&self.dir, series)));
            }
            out.retain(|p| p.ts_ms < start);
            // The same bound as the stored points: a point's start is in
            // the range.
            out.extend(
                RollupPoint::build(&rounds, tier.width_ms())
                    .into_iter()
                    .filter(|p| p.ts_ms >= from_ms),
            );
        }
        Ok(out)
    }

    /// The finest rollup tier that still holds the start of a range: the
    /// hourly files are kept for less time than the daily ones.
    fn covering_tier(&self, series: u64, finest: Tier, from_ms: i64) -> Result<Tier, StoreError> {
        if finest == Tier::R1d {
            return Ok(Tier::R1d);
        }
        let hourly = rollup::first_ts(&self.dir, series, Tier::R1h)?;
        if hourly.is_some_and(|h| h <= from_ms) {
            return Ok(Tier::R1h);
        }
        // Daily points older than every hourly one: hourly has expired
        // there.
        let daily = rollup::first_ts(&self.dir, series, Tier::R1d)?;
        let hourly_day = hourly.map(|h| h.div_euclid(layout::DAY_MS) * layout::DAY_MS);
        Ok(match (daily, hourly_day) {
            (Some(d), Some(h)) if d < h => Tier::R1d,
            (Some(_), None) => Tier::R1d,
            _ => Tier::R1h,
        })
    }

    /// Whether raw rounds hold the whole range: back to its start, or the
    /// range starts after the last day rolled up. Retention deletes only
    /// rolled-up days, so later rounds are all in segments or the WAL,
    /// even when no segment is left.
    fn raw_complete(&self, series: u64, from_ms: i64) -> Result<bool, StoreError> {
        let oldest_raw = layout::list_segments(&self.dir, series)?
            .first()
            .map(|s| s.day.saturating_mul(layout::DAY_MS));
        Ok(oldest_raw.is_some_and(|o| from_ms >= o)
            || rollup::last_rolled_day(&self.dir, series)?
                .is_none_or(|d| from_ms >= d.saturating_add(1).saturating_mul(layout::DAY_MS)))
    }

    /// After a raw read: retention may have deleted the oldest raw day
    /// between the choice and the listing, leaving no file to miss.
    fn still_raw(&self, series: u64, from_ms: i64) -> Result<(), StoreError> {
        if self.raw_complete(series, from_ms)? {
            Ok(())
        } else {
            Err(StoreError::Expired(layout::raw_dir(&self.dir, series)))
        }
    }

    /// After a tier read: retention may have deleted the hourly file that
    /// made the tier the right choice.
    fn still_tier(
        &self,
        series: u64,
        finest: Tier,
        chosen: Tier,
        from_ms: i64,
    ) -> Result<(), StoreError> {
        if self.covering_tier(series, finest, from_ms)? == chosen {
            Ok(())
        } else {
            Err(StoreError::Expired(rollup::tier_dir(
                &self.dir, series, chosen,
            )))
        }
    }

    /// Rounds for drawing a smoke graph of `from_ms..=to_ms`: the raw
    /// rounds while they cover the range, else one round per rollup point
    /// (its quantiles as the replies, and as many sent as keeps its loss
    /// ratio), with the point width as the step to draw at.
    pub fn read_graph(
        &self,
        series: u64,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<GraphRounds, StoreError> {
        retry(|| {
            if self.raw_complete(series, from_ms)? {
                let rounds = self.read(series, from_ms, to_ms)?;
                self.still_raw(series, from_ms)?;
                let sent = rounds.iter().map(|r| u64::from(r.sent)).sum();
                let received = rounds.iter().map(|r| r.rtts_us.len() as u64).sum();
                return Ok(GraphRounds {
                    resolution: Resolution::Raw,
                    rounds,
                    sent,
                    received,
                });
            }
            let tier = self.covering_tier(series, Tier::R1h, from_ms)?;
            let points = self.read_tier_once(series, tier, from_ms, to_ms)?;
            self.still_tier(series, Tier::R1h, tier, from_ms)?;
            Ok(GraphRounds {
                resolution: Resolution::Rollup(tier),
                rounds: points.iter().map(RollupPoint::to_round).collect(),
                sent: points.iter().map(|p| u64::from(p.sent)).sum(),
                received: points
                    .iter()
                    .map(|p| u64::from(p.received.min(p.sent)))
                    .sum(),
            })
        })
    }

    /// Points for drawing `from_ms..=to_ms` about `max_points` wide: the
    /// finest resolution with at most twice that many points, and not raw
    /// when the range starts before the oldest raw day still on disk.
    pub fn read_points(
        &self,
        series: u64,
        from_ms: i64,
        to_ms: i64,
        max_points: u32,
    ) -> Result<(Resolution, Vec<RollupPoint>), StoreError> {
        let span = to_ms.saturating_sub(from_ms).max(1);
        let step = i64::try_from(self.step_ms(series).unwrap_or(DEFAULT_STEP_MS))
            .unwrap_or(i64::MAX)
            .max(1);
        let limit = i64::from(max_points.max(1)) * 2;
        retry(|| {
            if span / step <= limit && self.raw_complete(series, from_ms)? {
                let rounds = self.read(series, from_ms, to_ms)?;
                self.still_raw(series, from_ms)?;
                return Ok((
                    Resolution::Raw,
                    rounds.iter().map(RollupPoint::from_round).collect(),
                ));
            }
            let finest = if span / Tier::R1h.width_ms() <= limit {
                Tier::R1h
            } else {
                Tier::R1d
            };
            let tier = self.covering_tier(series, finest, from_ms)?;
            let points = self.read_tier_once(series, tier, from_ms, to_ms)?;
            self.still_tier(series, finest, tier, from_ms)?;
            Ok((Resolution::Rollup(tier), points))
        })
    }

    /// Rounds of a series with `from_ms <= ts <= to_ms`, oldest first,
    /// from segments and from the WAL (rounds not yet in a segment).
    pub fn read(
        &self,
        series: u64,
        from_ms: i64,
        to_ms: i64,
    ) -> Result<Vec<StoredRound>, StoreError> {
        // The WAL first: a checkpoint running meanwhile moves its rounds
        // into segments before deleting it, so the segment pass below
        // still sees any round whose WAL file disappears.
        let mut wal_rounds: Vec<StoredRound> = Vec::new();
        for seq in layout::list_wal(&self.dir)? {
            let path = layout::wal_path(&self.dir, seq);
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                // Deleted by a checkpoint: its rounds are in segments now.
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let corrupt = |reason: &str| StoreError::Corrupt {
                path: path.clone(),
                reason: reason.to_string(),
            };
            let records = match wal::read(&bytes) {
                // The damaged record's series is unknown, so no read can
                // claim to be complete; the writer moves the file to
                // quarantine/ when it next starts.
                Ok((_, Tail::Corrupt)) => {
                    return Err(corrupt(
                        "bad record; restart the writer to set the file aside",
                    ));
                }
                // Complete records before a half-written one.
                Ok((records, _)) => records,
                // A file just created, its header not written yet.
                Err(_) if bytes.len() < wal::HEADER_LEN => continue,
                Err(e) => return Err(corrupt(e)),
            };
            wal_rounds.extend(
                records
                    .into_iter()
                    .filter(|(id, r)| *id == series && (from_ms..=to_ms).contains(&r.ts_ms))
                    .map(|(_, r)| r),
            );
        }

        let mut out: BTreeMap<i64, StoredRound> = BTreeMap::new();
        let (first_day, last_day) = (day_of(from_ms), day_of(to_ms));
        for seg in layout::list_segments(&self.dir, series)? {
            if seg.day < first_day || seg.day > last_day {
                continue;
            }
            let Some((bytes, sealed)) = self.read_segment(series, &seg)? else {
                continue;
            };
            let corrupt = |reason: &str| StoreError::Corrupt {
                path: seg.path.clone(),
                reason: reason.to_string(),
            };
            // An open segment just created, its header not written yet.
            if !sealed && bytes.len() < segment::HEADER_LEN {
                continue;
            }
            let scan = segment::scan(&bytes).map_err(corrupt)?;
            if scan.series != series || scan.day != seg.day {
                return Err(corrupt("header names another series or day"));
            }
            // An open segment may end in a half-written block; a complete
            // block with a bad checksum is damage in either kind of file.
            if scan.tail == Tail::Corrupt || (sealed && scan.tail != Tail::Clean) {
                return Err(corrupt("bad block"));
            }
            for r in segment::read_range(&bytes, &scan, from_ms, to_ms).map_err(corrupt)? {
                out.insert(r.ts_ms, r);
            }
        }
        for r in wal_rounds {
            out.entry(r.ts_ms).or_insert(r);
        }
        // WAL records carry the resolved address and timing only when they
        // change within the record (always, for single rounds), so the
        // forward fill done per block is already complete here.
        Ok(out.into_values().collect())
    }

    /// Check every WAL file, and every block of every segment: checksum,
    /// decoding, order. Files in `quarantine/` are reported too, as their
    /// rounds may be missing from [`Reader::read`].
    pub fn verify(&self) -> Result<VerifyReport, StoreError> {
        let mut rep = VerifyReport::default();
        for seq in layout::list_wal(&self.dir)? {
            let path = layout::wal_path(&self.dir, seq);
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            match wal::read(&bytes) {
                Ok((_, Tail::Corrupt)) => {
                    rep.problems.push(format!("{}: bad record", path.display()))
                }
                Ok(_) => {}
                Err(_) if bytes.len() < wal::HEADER_LEN => {}
                Err(e) => rep.problems.push(format!("{}: {e}", path.display())),
            }
        }
        // Files the writer set aside after damage: their rounds may be
        // missing from reads until someone has looked and removed them.
        match std::fs::read_dir(layout::quarantine_dir(&self.dir)) {
            Ok(entries) => {
                for e in entries {
                    rep.problems.push(format!(
                        "{}: set aside after damage; rounds it held may be missing \
                         (remove it once acknowledged)",
                        e?.path().display()
                    ));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        for id in layout::list_series_dirs(&self.dir)? {
            for seg in layout::list_segments(&self.dir, id)? {
                rep.segments += 1;
                let path = seg.path.display();
                let (bytes, sealed) = match self.read_segment(id, &seg) {
                    Ok(Some(b)) => b,
                    Ok(None) | Err(StoreError::Expired(_)) => continue,
                    Err(e) => return Err(e),
                };
                let scan = match segment::scan(&bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        rep.problems.push(format!("{path}: {e}"));
                        continue;
                    }
                };
                if scan.series != id || scan.day != seg.day {
                    rep.problems.push(format!(
                        "{path}: header names series {} day {}",
                        scan.series, scan.day
                    ));
                }
                match (scan.tail, sealed) {
                    (Tail::Clean, _) => {}
                    (Tail::Torn, false) => rep.torn_open += 1,
                    _ => rep
                        .problems
                        .push(format!("{path}: bad block after offset {}", scan.valid_len)),
                }
                let mut prev = i64::MIN;
                for &(offset, _) in &scan.blocks {
                    rep.blocks += 1;
                    let codec::Frame::Ok(body, _) = codec::read_frame(&bytes[offset..]) else {
                        rep.problems
                            .push(format!("{path}: block at {offset} unreadable"));
                        continue;
                    };
                    match codec::decode_block(body) {
                        Some(rounds) => {
                            for r in &rounds {
                                if r.ts_ms <= prev || day_of(r.ts_ms) != seg.day {
                                    rep.problems.push(format!(
                                        "{path}: round at {} out of order or outside its day",
                                        r.ts_ms
                                    ));
                                }
                                prev = r.ts_ms;
                            }
                            rep.rounds += rounds.len() as u64;
                        }
                        None => rep
                            .problems
                            .push(format!("{path}: block at {offset} does not decode")),
                    }
                }
            }
        }
        Ok(rep)
    }

    /// A listed segment's bytes, following a seal that renamed it after it
    /// was listed. Returns whether the file read is sealed.
    fn read_segment(
        &self,
        series: u64,
        seg: &layout::SegmentFile,
    ) -> Result<Option<(Vec<u8>, bool)>, StoreError> {
        let missing = |e: &io::Error| e.kind() == io::ErrorKind::NotFound;
        match std::fs::read(&seg.path) {
            Ok(b) => Ok(Some((b, seg.sealed))),
            Err(e) if missing(&e) && !seg.sealed => {
                let sealed = layout::segment_path(&self.dir, series, seg.day, true);
                match std::fs::read(&sealed) {
                    Ok(b) => Ok(Some((b, true))),
                    // Neither name: the open file was removed after its
                    // header write failed (it held no rounds), or set aside
                    // by recovery. Look once more in case it was re-created.
                    Err(e) if missing(&e) => match std::fs::read(&seg.path) {
                        Ok(b) => Ok(Some((b, false))),
                        Err(e) if missing(&e) => Ok(None),
                        Err(e) => Err(e.into()),
                    },
                    Err(e) => Err(e.into()),
                }
            }
            // Deleted by retention after it was listed.
            Err(e) if missing(&e) => Err(StoreError::Expired(seg.path.clone())),
            Err(e) => Err(e.into()),
        }
    }

    /// Total bytes of segment files (apparent size, not disk blocks).
    pub fn segment_bytes(&self) -> Result<u64, StoreError> {
        let mut total = 0;
        for id in layout::list_series_dirs(&self.dir)? {
            for seg in layout::list_segments(&self.dir, id)? {
                total += match std::fs::metadata(&seg.path) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound && !seg.sealed => {
                        match std::fs::metadata(layout::segment_path(&self.dir, id, seg.day, true))
                        {
                            // Gone under both names (see `read_segment`).
                            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                            m => m?,
                        }
                    }
                    // Deleted by retention after it was listed.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    m => m?,
                }
                .len();
            }
        }
        Ok(total)
    }
}
