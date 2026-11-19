//! Rollup tiers that keep the smoke (architecture doc §6.4, §21.3 E4).
//!
//! A rollup point consolidates the rounds of one hour (`r1h`) or one UTC
//! day (`r1d`): it keeps [`QUANTILES`] quantiles of the union of their
//! samples, plus rounds, samples sent and received. Both tiers are built
//! exactly from the raw rounds when a day's segment is sealed, while the
//! raw data is still on disk, so no sketch (and no sketch error) is needed:
//! the 1-day tier never re-reads more than one day of raw data.
//!
//! Files: `series/<id>/r1h/YYYY-MM.roll` (one month) and
//! `series/<id>/r1d/YYYY.roll` (one year). Each is a header followed by
//! CRC-framed records, one record per day holding that day's points.
//! Records are appended in day order; a torn last record (a crash during
//! the append) is cut off and rewritten on the next build. A new file is
//! written under a temporary name and renamed into place with its header
//! and first record, so a crash never leaves a file with a partial header.
//! Retention deletes whole files.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::codec::{self, Frame};
use crate::layout::{self, DAY_MS, date};
use crate::round::StoredRound;
use crate::varint::{self, Reader};

/// Quantiles per rollup point (matches the default 20 pings per round).
pub const QUANTILES: usize = 20;
/// Most replies a rollup point stands for in a graph
/// ([`RollupPoint::to_round`]): enough to keep the loss ratio to 0.2 %,
/// few enough that ten years of daily points stay small.
pub const GRAPH_SAMPLES: u64 = 500;
const HOUR_MS: i64 = 3_600_000;
const MAGIC: &[u8; 8] = b"RLROL\0\0\x01";
const HEADER_LEN: usize = 8 + 8 + 1 + 4;

/// A consolidation tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tier {
    /// One point per hour.
    R1h,
    /// One point per UTC day.
    R1d,
}

impl Tier {
    pub const ALL: [Tier; 2] = [Tier::R1h, Tier::R1d];

    /// Width of one point.
    pub fn width_ms(self) -> i64 {
        match self {
            Self::R1h => HOUR_MS,
            Self::R1d => DAY_MS,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::R1h => "r1h",
            Self::R1d => "r1d",
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::R1h => 1,
            Self::R1d => 2,
        }
    }

    /// File holding `day`: its month for r1h, its year for r1d.
    fn file_stem(self, day: i64) -> String {
        let d = date(day);
        match self {
            Self::R1h => d[..7].to_string(),
            Self::R1d => d[..4].to_string(),
        }
    }

    /// First day after the period a file covers, from its stem.
    fn file_end(self, stem: &str) -> Option<i64> {
        match self {
            Self::R1h => {
                let (y, m) = stem.split_once('-')?;
                let (y, m): (i64, i64) = (y.parse().ok()?, m.parse().ok()?);
                let (y, m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
                layout::parse_date(&format!("{y:04}-{m:02}-01"))
            }
            Self::R1d => {
                let y: i64 = stem.parse().ok()?;
                layout::parse_date(&format!("{:04}-01-01", y + 1))
            }
        }
    }
}

/// One consolidated point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollupPoint {
    /// Start of the hour or day, Unix milliseconds.
    pub ts_ms: i64,
    /// Rounds consolidated.
    pub rounds: u32,
    pub sent: u32,
    pub received: u32,
    /// [`QUANTILES`] RTTs (µs) at evenly spaced ranks of all received
    /// samples, from the minimum to the maximum; empty when nothing was
    /// received.
    pub quantiles_us: Vec<u32>,
}

impl RollupPoint {
    /// Points from rounds: one per `width_ms` bucket that holds rounds,
    /// oldest first. `rounds` must be sorted by time.
    pub fn build(rounds: &[StoredRound], width_ms: i64) -> Vec<RollupPoint> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < rounds.len() {
            let bucket = rounds[i].ts_ms.div_euclid(width_ms) * width_ms;
            let mut j = i;
            let mut samples = Vec::new();
            let (mut sent, mut received) = (0u32, 0u32);
            while j < rounds.len() && rounds[j].ts_ms.div_euclid(width_ms) * width_ms == bucket {
                let r = &rounds[j];
                sent += u32::from(r.sent);
                received += u32::try_from(r.rtts_us.len()).unwrap_or(u32::MAX);
                samples.extend_from_slice(&r.rtts_us);
                j += 1;
            }
            samples.sort_unstable();
            out.push(RollupPoint {
                ts_ms: bucket,
                rounds: u32::try_from(j - i).unwrap_or(u32::MAX),
                sent,
                received,
                quantiles_us: quantiles(&samples),
            });
            i = j;
        }
        out
    }

    /// The point as one round for the smoke graph: its quantiles stand
    /// for the replies, repeated so that sent and received keep their
    /// ratio (both scaled down together past [`GRAPH_SAMPLES`] replies or
    /// `u16::MAX` sent).
    pub fn to_round(&self) -> StoredRound {
        let sent = u64::from(self.sent);
        let received = u64::from(self.received.min(self.sent));
        let scale = received
            .div_ceil(GRAPH_SAMPLES)
            .max(sent.div_ceil(u64::from(u16::MAX)))
            .max(1);
        // Sent rounds up and replies down, so some loss stays some; no
        // loss stays none, and some replies stay at least one.
        let scaled_sent = sent.div_ceil(scale);
        let replies = if received == sent {
            scaled_sent
        } else {
            (received / scale).max(u64::from(received > 0))
        };
        let sent = scaled_sent;
        let q = &self.quantiles_us;
        let rtts_us = if q.is_empty() {
            Vec::new()
        } else {
            // Reply k of n takes the quantile at the same rank.
            (0..replies)
                .map(|k| q[usize::try_from(k * q.len() as u64 / replies).unwrap_or(0)])
                .collect()
        };
        StoredRound {
            ts_ms: self.ts_ms,
            sent: u16::try_from(sent).unwrap_or(u16::MAX),
            rtts_us,
            errors: crate::round::ErrorCounts::default(),
            resolved: None,
            timing: None,
            flags: 0,
        }
    }

    /// One raw round as a point, so callers can treat every tier alike.
    pub fn from_round(r: &StoredRound) -> RollupPoint {
        RollupPoint {
            ts_ms: r.ts_ms,
            rounds: 1,
            sent: u32::from(r.sent),
            received: u32::try_from(r.rtts_us.len()).unwrap_or(u32::MAX),
            quantiles_us: quantiles(&r.rtts_us),
        }
    }
}

/// [`QUANTILES`] values at ranks `round(i × (n − 1) / (Q − 1))` of a sorted
/// slice: the first is the minimum, the last the maximum.
pub fn quantiles(sorted: &[u32]) -> Vec<u32> {
    let n = sorted.len();
    if n == 0 {
        return Vec::new();
    }
    (0..QUANTILES)
        .map(|i| sorted[(i * (n - 1) + (QUANTILES - 1) / 2) / (QUANTILES - 1)])
        .collect()
}

fn encode(points: &[RollupPoint]) -> Vec<u8> {
    let mut out = Vec::new();
    varint::put_u64(&mut out, points.len() as u64);
    let mut prev_ts = 0i64;
    for p in points {
        varint::put_i64(&mut out, p.ts_ms - prev_ts);
        prev_ts = p.ts_ms;
        varint::put_u64(&mut out, u64::from(p.rounds));
        varint::put_u64(&mut out, u64::from(p.sent));
        varint::put_u64(&mut out, u64::from(p.received));
        // Sorted: the first value, then non-negative rank-to-rank deltas.
        let mut prev = 0u32;
        for &q in &p.quantiles_us {
            varint::put_u64(&mut out, u64::from(q - prev));
            prev = q;
        }
    }
    out
}

fn decode(body: &[u8]) -> Option<Vec<RollupPoint>> {
    let mut r = Reader::new(body);
    let n = usize::try_from(r.u64()?).ok()?;
    let mut out = Vec::with_capacity(n.min(1024));
    let mut ts = 0i64;
    for _ in 0..n {
        ts = ts.checked_add(r.i64()?)?;
        let rounds = r.u32()?;
        let sent = r.u32()?;
        let received = r.u32()?;
        if received > sent {
            return None;
        }
        let mut quantiles_us = Vec::new();
        if received > 0 {
            let mut prev = 0u32;
            for _ in 0..QUANTILES {
                prev = prev.checked_add(r.u32()?)?;
                quantiles_us.push(prev);
            }
        }
        out.push(RollupPoint {
            ts_ms: ts,
            rounds,
            sent,
            received,
            quantiles_us,
        });
    }
    r.is_empty().then_some(out)
}

pub(crate) fn tier_dir(dir: &Path, series: u64, tier: Tier) -> PathBuf {
    dir.join("series")
        .join(series.to_string())
        .join(tier.name())
}

fn file_path(dir: &Path, series: u64, tier: Tier, day: i64) -> PathBuf {
    tier_dir(dir, series, tier).join(format!("{}.roll", tier.file_stem(day)))
}

fn header(series: u64, tier: Tier) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&series.to_le_bytes());
    h.push(tier.code());
    let crc = crc32c::crc32c(&h);
    h.extend_from_slice(&crc.to_le_bytes());
    h
}

/// The records of a file held in memory, and the length of its valid part.
/// A torn last record is left out; a corrupt one is an error.
fn parse(bytes: &[u8], series: u64, tier: Tier) -> Result<(Vec<RollupPoint>, usize), &'static str> {
    let h = bytes
        .get(..HEADER_LEN)
        .ok_or("rollup header is truncated")?;
    if h != header(series, tier).as_slice() {
        return Err("rollup header is wrong or names another series or tier");
    }
    let mut pos = HEADER_LEN;
    let mut points = Vec::new();
    while pos < bytes.len() {
        match codec::read_frame(&bytes[pos..]) {
            Frame::Ok(body, len) => {
                points.extend(decode(body).ok_or("undecodable rollup record")?);
                pos += len;
            }
            Frame::Truncated => break,
            Frame::Corrupt => return Err("bad rollup record checksum"),
        }
    }
    Ok((points, pos))
}

fn corrupt(path: &Path, reason: &str) -> crate::StoreError {
    crate::StoreError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    }
}

/// Append one day's points to the tier's file, unless the file already
/// has points of that day or later (a rebuild after a crash). Durable on
/// return.
pub(crate) fn append_day(
    dir: &Path,
    series: u64,
    tier: Tier,
    day: i64,
    points: &[RollupPoint],
) -> Result<(), crate::StoreError> {
    if points.is_empty() {
        return Ok(());
    }
    let path = file_path(dir, series, tier, day);
    let existing = match std::fs::read(&path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let mut file = match existing {
        Some(bytes) => {
            let (old, valid) = parse(&bytes, series, tier).map_err(|r| corrupt(&path, r))?;
            if old.last().is_some_and(|p| p.ts_ms >= day * DAY_MS) {
                // Written before a crash, maybe not yet on disk: the raw
                // day may be deleted once this returns.
                sync_tier(dir, series, tier, &path)?;
                return Ok(());
            }
            let f = OpenOptions::new().write(true).open(&path)?;
            // Cut a torn record left by a crash.
            f.set_len(valid as u64)?;
            f
        }
        None => {
            let parent = tier_dir(dir, series, tier);
            std::fs::create_dir_all(&parent)?;
            let mut bytes = header(series, tier);
            codec::put_frame(&mut bytes, &encode(points));
            // A leftover from a crash before the rename holds nothing that
            // is not rebuilt here.
            let tmp = path.with_extension("roll.tmp");
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_data()?;
            drop(f);
            std::fs::rename(&tmp, &path)?;
            layout::sync_dir(&parent)?;
            if let Some(series_dir) = parent.parent() {
                layout::sync_dir(series_dir)?;
            }
            return Ok(());
        }
    };
    let mut frame = Vec::new();
    codec::put_frame(&mut frame, &encode(points));
    use std::io::Seek;
    file.seek(io::SeekFrom::End(0))?;
    file.write_all(&frame)?;
    file.sync_data()?;
    Ok(())
}

/// Sync a tier file and the directories naming it.
fn sync_tier(dir: &Path, series: u64, tier: Tier, path: &Path) -> Result<(), crate::StoreError> {
    OpenOptions::new().write(true).open(path)?.sync_data()?;
    let parent = tier_dir(dir, series, tier);
    layout::sync_dir(&parent)?;
    if let Some(series_dir) = parent.parent() {
        layout::sync_dir(series_dir)?;
    }
    Ok(())
}

/// Sync every rollup file of a series, and their directories: called
/// before raw days are deleted, as a rollup written before a crash may
/// still be only in the page cache.
pub(crate) fn sync_all(dir: &Path, series: u64) -> Result<(), crate::StoreError> {
    for tier in Tier::ALL {
        let files = list(dir, series, tier)?;
        for (_, path) in &files {
            OpenOptions::new().write(true).open(path)?.sync_data()?;
        }
        if !files.is_empty() {
            layout::sync_dir(&tier_dir(dir, series, tier))?;
        }
    }
    layout::sync_dir(&dir.join("series").join(series.to_string()))?;
    Ok(())
}

/// Time of the oldest point of a tier, if it has any.
pub(crate) fn first_ts(
    dir: &Path,
    series: u64,
    tier: Tier,
) -> Result<Option<i64>, crate::StoreError> {
    for (_, path) in list(dir, series, tier)? {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            // Expired meanwhile: the next file is the oldest.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let (points, _) = parse(&bytes, series, tier).map_err(|r| corrupt(&path, r))?;
        if let Some(p) = points.first() {
            return Ok(Some(p.ts_ms));
        }
    }
    Ok(None)
}

/// Points of a tier with `from_ms <= ts <= to_ms`, oldest first.
pub(crate) fn read(
    dir: &Path,
    series: u64,
    tier: Tier,
    from_ms: i64,
    to_ms: i64,
) -> Result<Vec<RollupPoint>, crate::StoreError> {
    let mut out = Vec::new();
    for (stem, path) in list(dir, series, tier)? {
        let Some(end) = tier.file_end(&stem) else {
            continue;
        };
        // Files wholly outside the range are not read.
        if end * DAY_MS <= from_ms || start_of(tier, &stem).is_some_and(|s| s * DAY_MS > to_ms) {
            continue;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let (points, _) = parse(&bytes, series, tier).map_err(|r| corrupt(&path, r))?;
        out.extend(
            points
                .into_iter()
                .filter(|p| (from_ms..=to_ms).contains(&p.ts_ms)),
        );
    }
    Ok(out)
}

fn start_of(tier: Tier, stem: &str) -> Option<i64> {
    match tier {
        Tier::R1h => layout::parse_date(&format!("{stem}-01")),
        Tier::R1d => layout::parse_date(&format!("{stem}-01-01")),
    }
}

/// Rollup files of a series' tier, sorted by period: `(stem, path)`.
fn list(dir: &Path, series: u64, tier: Tier) -> io::Result<Vec<(String, PathBuf)>> {
    let entries = match std::fs::read_dir(tier_dir(dir, series, tier)) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".roll")) else {
            continue;
        };
        if tier.file_end(stem).is_some() {
            out.push((stem.to_string(), entry.path()));
        }
    }
    out.sort();
    Ok(out)
}

/// The newest day with an r1d point, if any. Both tiers of a day are
/// written r1h first, so an r1d point means the day is fully rolled up.
pub(crate) fn last_rolled_day(dir: &Path, series: u64) -> Result<Option<i64>, crate::StoreError> {
    for (_, path) in list(dir, series, Tier::R1d)?.into_iter().rev() {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            // Expired by a writer while a reader looks.
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let (points, _) = parse(&bytes, series, Tier::R1d).map_err(|r| corrupt(&path, r))?;
        if let Some(p) = points.last() {
            return Ok(Some(p.ts_ms.div_euclid(DAY_MS)));
        }
    }
    Ok(None)
}

/// Delete whole files of a tier whose period ended before `before_day`.
/// Returns how many were deleted.
pub(crate) fn expire(
    dir: &Path,
    series: u64,
    tier: Tier,
    before_day: i64,
) -> Result<usize, crate::StoreError> {
    let mut n = 0;
    for (stem, path) in list(dir, series, tier)? {
        if tier.file_end(&stem).is_some_and(|end| end <= before_day) {
            std::fs::remove_file(&path)?;
            n += 1;
        }
    }
    if n > 0 {
        layout::sync_dir(&tier_dir(dir, series, tier))?;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::round::ErrorCounts;
    use proptest::prelude::*;

    fn round(ts_ms: i64, sent: u16, rtts: &[u32]) -> StoredRound {
        let mut rtts_us = rtts.to_vec();
        rtts_us.sort_unstable();
        StoredRound {
            ts_ms,
            sent,
            rtts_us,
            errors: ErrorCounts::default(),
            resolved: None,
            timing: None,
            flags: 0,
        }
    }

    #[test]
    fn quantiles_span_min_to_max() {
        let v: Vec<u32> = (1..=100).collect();
        let q = quantiles(&v);
        assert_eq!(q.len(), QUANTILES);
        assert_eq!((q[0], q[QUANTILES - 1]), (1, 100));
        assert!(q.windows(2).all(|w| w[0] <= w[1]));
        assert_eq!(quantiles(&[7]), vec![7; QUANTILES]);
        assert!(quantiles(&[]).is_empty());
    }

    #[test]
    fn graph_rounds_keep_the_loss_ratio() {
        let point = |sent, received| RollupPoint {
            ts_ms: 0,
            rounds: 288,
            sent,
            received,
            quantiles_us: if received > 0 {
                (1..=20).collect()
            } else {
                Vec::new()
            },
        };
        let r = point(240, 238).to_round();
        assert_eq!((r.sent, r.rtts_us.len()), (240, 238));
        assert_eq!((r.rtts_us[0], r.rtts_us[237]), (1, 20));
        // A day of 1 s rounds: scaled down, ratio kept to the sample.
        let r = point(1_728_000, 1_700_000).to_round();
        assert!(r.rtts_us.len() as u64 <= GRAPH_SAMPLES);
        let loss = 1.0 - r.rtts_us.len() as f64 / f64::from(r.sent);
        assert!((loss - 28_000.0 / 1_728_000.0).abs() < 0.005, "{loss}");
        let r = point(5760, 5760).to_round();
        assert_eq!(r.rtts_us.len(), usize::from(r.sent));
        let r = point(5760, 0).to_round();
        assert!(r.sent > 0 && r.rtts_us.is_empty());
        let r = point(100_000, 1).to_round();
        assert_eq!(r.rtts_us.len(), 1);
        assert!(r.sent > 1);
    }

    #[test]
    fn hourly_points_consolidate_their_rounds() {
        let rounds = [
            round(0, 3, &[10, 30]),
            round(300_000, 3, &[20]),
            round(HOUR_MS, 2, &[]),
        ];
        let p = RollupPoint::build(&rounds, HOUR_MS);
        assert_eq!(p.len(), 2);
        assert_eq!((p[0].rounds, p[0].sent, p[0].received), (2, 6, 3));
        assert_eq!((p[0].quantiles_us[0], p[0].quantiles_us[19]), (10, 30));
        assert_eq!((p[1].ts_ms, p[1].received), (HOUR_MS, 0));
        assert!(p[1].quantiles_us.is_empty());
    }

    proptest! {
        #[test]
        fn records_round_trip(points in prop::collection::vec(
            (0i64..1_000_000, 1u32..300, 0u32..100, prop::collection::vec(0u32..5_000_000, 0..60)),
            0..30,
        )) {
            let mut ts = 1_700_000_000_000i64;
            let points: Vec<RollupPoint> = points.into_iter().map(|(gap, rounds, extra, mut s)| {
                ts += gap;
                s.sort_unstable();
                let received = s.len() as u32;
                RollupPoint { ts_ms: ts, rounds, sent: received + extra, received, quantiles_us: quantiles(&s) }
            }).collect();
            prop_assert_eq!(decode(&encode(&points)), Some(points));
        }

        /// Exact quantiles: each rollup quantile is one of the samples at
        /// its rank in the union of the hour's rounds.
        #[test]
        fn rollup_quantiles_are_exact(rounds in prop::collection::vec(
            prop::collection::vec(1u32..1_000_000, 0..25), 1..12,
        )) {
            let stored: Vec<StoredRound> = rounds.iter().enumerate()
                .map(|(i, r)| round(i as i64 * 300_000, 25, r)).collect();
            let p = RollupPoint::build(&stored, HOUR_MS);
            let mut all: Vec<u32> = rounds.concat();
            all.sort_unstable();
            prop_assert_eq!(p.len(), 1);
            prop_assert_eq!(&p[0].quantiles_us, &quantiles(&all));
        }
    }

    #[test]
    fn files_append_skip_repeats_and_survive_a_torn_record() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let day = 20_000;
        let p = |h: i64| RollupPoint {
            ts_ms: day * DAY_MS + h * HOUR_MS,
            rounds: 12,
            sent: 240,
            received: 239,
            quantiles_us: vec![1000; QUANTILES],
        };
        append_day(d, 7, Tier::R1h, day, &[p(0), p(1)]).unwrap();
        // A rebuild of the same day is skipped.
        append_day(d, 7, Tier::R1h, day, &[p(0), p(1)]).unwrap();
        assert_eq!(read(d, 7, Tier::R1h, 0, i64::MAX).unwrap().len(), 2);

        // A torn record at the end is cut by the next append.
        let path = file_path(d, 7, Tier::R1h, day);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[9, 0, 0, 0, 1, 2]).unwrap();
        drop(f);
        assert_eq!(read(d, 7, Tier::R1h, 0, i64::MAX).unwrap().len(), 2);
        let next = RollupPoint {
            ts_ms: (day + 1) * DAY_MS,
            ..p(0)
        };
        append_day(d, 7, Tier::R1h, day + 1, std::slice::from_ref(&next)).unwrap();
        let all = read(d, 7, Tier::R1h, 0, i64::MAX).unwrap();
        assert_eq!(all, vec![p(0), p(1), next]);
    }

    #[test]
    fn last_day_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        assert_eq!(last_rolled_day(d, 1).unwrap(), None);
        // 2024-12-31 and 2025-01-01 land in different yearly files.
        let a = layout::parse_date("2024-12-31").unwrap();
        let b = a + 1;
        for day in [a, b] {
            let pt = RollupPoint {
                ts_ms: day * DAY_MS,
                rounds: 288,
                sent: 5760,
                received: 5760,
                quantiles_us: vec![5; QUANTILES],
            };
            append_day(d, 1, Tier::R1d, day, &[pt]).unwrap();
        }
        assert_eq!(last_rolled_day(d, 1).unwrap(), Some(b));
        assert_eq!(
            read(d, 1, Tier::R1d, b * DAY_MS, i64::MAX).unwrap().len(),
            1
        );
        assert_eq!(expire(d, 1, Tier::R1d, b).unwrap(), 1);
        assert_eq!(read(d, 1, Tier::R1d, 0, i64::MAX).unwrap().len(), 1);
    }
}
