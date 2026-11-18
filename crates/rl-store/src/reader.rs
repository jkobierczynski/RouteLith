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
        let mut out: BTreeMap<i64, StoredRound> = BTreeMap::new();
        let (first_day, last_day) = (day_of(from_ms), day_of(to_ms));
        for seg in layout::list_segments(&self.dir, series)? {
            if seg.day < first_day || seg.day > last_day {
                continue;
            }
            let bytes = match std::fs::read(&seg.path) {
                Ok(b) => b,
                // Sealed between listing and reading: read the new name.
                Err(e) if e.kind() == io::ErrorKind::NotFound && !seg.sealed => {
                    let sealed = layout::segment_path(&self.dir, series, seg.day, true);
                    std::fs::read(sealed)?
                }
                Err(e) => return Err(e.into()),
            };
            let corrupt = |reason: &str| StoreError::Corrupt {
                path: seg.path.clone(),
                reason: reason.to_string(),
            };
            let scan = segment::scan(&bytes).map_err(corrupt)?;
            if seg.sealed && scan.tail != Tail::Clean {
                return Err(corrupt("bad block"));
            }
            for r in segment::read_range(&bytes, &scan, from_ms, to_ms).map_err(corrupt)? {
                out.insert(r.ts_ms, r);
            }
        }
        for seq in layout::list_wal(&self.dir)? {
            let bytes = match std::fs::read(layout::wal_path(&self.dir, seq)) {
                Ok(b) => b,
                // Deleted by a checkpoint: its rounds are in segments now.
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let Ok((records, _)) = wal::read(&bytes) else {
                continue;
            };
            for (id, r) in records {
                if id == series && (from_ms..=to_ms).contains(&r.ts_ms) {
                    out.entry(r.ts_ms).or_insert(r);
                }
            }
        }
        // WAL records carry the resolved address and timing only when they
        // change within the record (always, for single rounds), so the
        // forward fill done per block is already complete here.
        Ok(out.into_values().collect())
    }

    /// Check every block of every segment: checksum, decoding, order.
    pub fn verify(&self) -> Result<VerifyReport, StoreError> {
        let mut rep = VerifyReport::default();
        for id in layout::list_series_dirs(&self.dir)? {
            for seg in layout::list_segments(&self.dir, id)? {
                rep.segments += 1;
                let path = seg.path.display();
                let bytes = std::fs::read(&seg.path)?;
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
                match (scan.tail, seg.sealed) {
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

    /// Total bytes of segment files (apparent size, not disk blocks).
    pub fn segment_bytes(&self) -> Result<u64, StoreError> {
        let mut total = 0;
        for id in layout::list_series_dirs(&self.dir)? {
            for seg in layout::list_segments(&self.dir, id)? {
                total += std::fs::metadata(&seg.path)?.len();
            }
        }
        Ok(total)
    }
}
