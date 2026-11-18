//! Reading a data directory, also while a server writes to it.
//!
//! Sealed segments never change. An open segment or WAL file may end in a
//! half-written frame; readers stop there, as recovery would.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::index::{self, SeriesKey};
use crate::layout::{self, day_of};
use crate::round::StoredRound;
use crate::segment::{self, Tail};
use crate::{StoreError, codec, wal};

/// Read access to a data directory.
#[derive(Debug)]
pub struct Reader {
    dir: PathBuf,
    series: Vec<(SeriesKey, u64)>,
}

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

impl Reader {
    /// Open a data directory and load its series index.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            dir: dir.to_path_buf(),
            series: index::load(dir)?,
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
                let Some((bytes, sealed)) = self.read_segment(id, &seg)? else {
                    continue;
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
                    m => m?,
                }
                .len();
            }
        }
        Ok(total)
    }
}
