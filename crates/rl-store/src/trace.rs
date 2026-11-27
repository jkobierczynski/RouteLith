//! The raw trace tier (architecture doc §21.9 P7): every sweep of a trace,
//! kept for a few days for second-by-second zoom and route-change evidence.
//!
//! ```text
//! series/<id>/trace/
//! ├── 2026-11-26.seg    sealed day: zstd blocks
//! └── 2026-11-27.open   today: one CRC frame per record
//! ```
//!
//! Both files start with `b"RLTRC\0\0\x01" | series: u64 LE | day: i64 LE |
//! crc32c: u32 LE`. An open file then holds frames whose body starts with
//! a tag: `0` defines the next entry of the day's address table (family
//! byte 4 or 6, then the address), `1` is a sweep:
//!
//! ```text
//! ms since the day's start (varint) | timing code (0 = unknown) | hops (varint)
//! per hop: kind | [address index + 1 (varint, 0 = none) | code (unreachable)
//!          | RTT in 10 µs units (varint)]
//! ```
//!
//! Sealing compresses the open file's frames into tag `2` frames (zstd) and
//! renames the result to `.seg`. Appends are buffered and made durable by
//! [`TraceLog::sync`], which the server calls once a second like the WAL's
//! fsync, so a crash loses at most the last second of sweeps; a torn last
//! frame is cut off when the file is next opened.
//!
//! Sweeps overlap and can finish out of order, so records are not required
//! to be in time order; readers sort them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use rl_core::TimingBackend;

use crate::StoreError;
use crate::codec::{self, Frame};
use crate::layout::{self, DAY_MS, date, day_of, parse_date};
use crate::varint::{self, Reader};

const MAGIC: &[u8; 8] = b"RLTRC\0\0\x01";
const HEADER_LEN: usize = 8 + 8 + 8 + 4;
const TAG_ADDR: u8 = 0;
const TAG_SWEEP: u8 = 1;
const TAG_BLOCK: u8 = 2;
/// Uncompressed bytes per sealed block.
const BLOCK_BYTES: usize = 1 << 20;
const ZSTD_LEVEL: i32 = 3;
/// An open day stays open this long after UTC midnight for late sweeps.
const SEAL_GRACE_MS: i64 = 10 * 60 * 1000;
/// RTTs are kept in units of this many microseconds.
pub const RTT_UNIT_US: u32 = 10;

const KIND_LOST: u8 = 0;
const KIND_SEND_FAILED: u8 = 1;
const KIND_TIME_EXCEEDED: u8 = 2;
const KIND_REPLY: u8 = 3;
const KIND_UNREACHABLE: u8 = 4;

/// One TTL of a stored sweep. RTTs are multiples of [`RTT_UNIT_US`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceHop {
    Lost,
    /// The probe never left this host.
    SendFailed,
    /// A router answered: the path goes on.
    TimeExceeded {
        from: IpAddr,
        rtt_us: u32,
    },
    /// The destination answered.
    Reply {
        from: IpAddr,
        rtt_us: u32,
    },
    /// Destination unreachable: the path ends here.
    Unreachable {
        from: Option<IpAddr>,
        code: u8,
        rtt_us: u32,
    },
}

impl TraceHop {
    pub fn responder(&self) -> Option<IpAddr> {
        match *self {
            Self::TimeExceeded { from, .. } | Self::Reply { from, .. } => Some(from),
            Self::Unreachable { from, .. } => from,
            Self::Lost | Self::SendFailed => None,
        }
    }

    pub fn rtt_us(&self) -> Option<u32> {
        match *self {
            Self::TimeExceeded { rtt_us, .. }
            | Self::Reply { rtt_us, .. }
            | Self::Unreachable { rtt_us, .. } => Some(rtt_us),
            Self::Lost | Self::SendFailed => None,
        }
    }
}

/// One sweep as stored: `hops[i]` is TTL `i + 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceRecord {
    /// Sweep start, Unix milliseconds (UTC).
    pub ts_ms: i64,
    pub timing: Option<TimingBackend>,
    pub hops: Vec<TraceHop>,
}

/// `data/series/<id>/trace`.
pub fn trace_dir(dir: &Path, series: u64) -> PathBuf {
    dir.join("series").join(series.to_string()).join("trace")
}

fn day_path(dir: &Path, series: u64, day: i64, sealed: bool) -> PathBuf {
    let ext = if sealed { "seg" } else { "open" };
    trace_dir(dir, series).join(format!("{}.{ext}", date(day)))
}

fn header(series: u64, day: i64) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&series.to_le_bytes());
    h.extend_from_slice(&day.to_le_bytes());
    let crc = crc32c::crc32c(&h);
    h.extend_from_slice(&crc.to_le_bytes());
    h
}

fn check_header(bytes: &[u8], series: u64, day: i64) -> Result<(), &'static str> {
    let h = bytes
        .get(..HEADER_LEN)
        .ok_or("trace file header is truncated")?;
    if &h[..8] != MAGIC {
        return Err("not a trace file (bad magic)");
    }
    if crc32c::crc32c(&h[..24]).to_le_bytes() != h[24..28] {
        return Err("trace file header checksum mismatch");
    }
    if h[8..16] != series.to_le_bytes() || h[16..24] != day.to_le_bytes() {
        return Err("trace file belongs to another series or day");
    }
    Ok(())
}

/// The frames of a body, up to the first damaged or torn one, and the
/// length of that valid prefix.
fn frames(body: &[u8]) -> (Vec<&[u8]>, usize) {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        match codec::read_frame(&body[pos..]) {
            Frame::Ok(b, len) => {
                out.push(b);
                pos += len;
            }
            Frame::Truncated | Frame::Corrupt => break,
        }
    }
    (out, pos)
}

fn put_addr(out: &mut Vec<u8>, addr: IpAddr) {
    out.push(TAG_ADDR);
    match addr {
        IpAddr::V4(a) => {
            out.push(4);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            out.push(6);
            out.extend_from_slice(&a.octets());
        }
    }
}

fn read_addr(r: &mut Reader<'_>) -> Option<IpAddr> {
    match r.byte()? {
        4 => {
            let b: [u8; 4] = r.bytes(4)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(b)))
        }
        6 => {
            let b: [u8; 16] = r.bytes(16)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

fn units(rtt_us: u32) -> u64 {
    u64::from(rtt_us.saturating_add(RTT_UNIT_US / 2) / RTT_UNIT_US)
}

/// Decodes the frames of one day, in file order.
#[derive(Default)]
struct Decoder {
    day_start: i64,
    addrs: Vec<IpAddr>,
}

impl Decoder {
    fn frame(&mut self, body: &[u8], out: &mut Vec<TraceRecord>) -> Option<()> {
        let mut r = Reader::new(body);
        match r.byte()? {
            TAG_ADDR => self.addrs.push(read_addr(&mut r)?),
            TAG_SWEEP => out.push(self.sweep(&mut r)?),
            TAG_BLOCK => {
                let inner =
                    zstd::bulk::decompress(r.bytes(body.len() - 1)?, codec::MAX_FRAME).ok()?;
                let (inner_frames, len) = frames(&inner);
                if len != inner.len() {
                    return None;
                }
                for f in inner_frames {
                    self.frame(f, out)?;
                }
            }
            _ => return None,
        }
        Some(())
    }

    fn sweep(&self, r: &mut Reader<'_>) -> Option<TraceRecord> {
        let offset = i64::try_from(r.u64()?).ok().filter(|&o| o < DAY_MS)?;
        let timing = match r.byte()? {
            0 => None,
            c => Some(TimingBackend::from_code(c)?),
        };
        let n = usize::try_from(r.u64()?).ok().filter(|&n| n <= 255)?;
        let mut hops = Vec::with_capacity(n);
        let addr = |r: &mut Reader<'_>| -> Option<Option<IpAddr>> {
            match r.u64()? {
                0 => Some(None),
                i => Some(Some(*self.addrs.get(usize::try_from(i - 1).ok()?)?)),
            }
        };
        let rtt = |r: &mut Reader<'_>| -> Option<u32> {
            u32::try_from(r.u64()?.checked_mul(u64::from(RTT_UNIT_US))?).ok()
        };
        for _ in 0..n {
            hops.push(match r.byte()? {
                KIND_LOST => TraceHop::Lost,
                KIND_SEND_FAILED => TraceHop::SendFailed,
                KIND_TIME_EXCEEDED => TraceHop::TimeExceeded {
                    from: addr(r)??,
                    rtt_us: rtt(r)?,
                },
                KIND_REPLY => TraceHop::Reply {
                    from: addr(r)??,
                    rtt_us: rtt(r)?,
                },
                KIND_UNREACHABLE => TraceHop::Unreachable {
                    from: addr(r)?,
                    code: r.byte()?,
                    rtt_us: rtt(r)?,
                },
                _ => return None,
            });
        }
        r.is_empty().then_some(TraceRecord {
            ts_ms: self.day_start + offset,
            timing,
            hops,
        })
    }
}

/// Records of one day file; a damaged frame ends the read (an open file's
/// torn tail is normal after a crash).
fn read_day(path: &Path, series: u64, day: i64) -> Result<Vec<TraceRecord>, StoreError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    check_header(&bytes, series, day).map_err(|reason| StoreError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    })?;
    let mut dec = Decoder {
        day_start: day * DAY_MS,
        addrs: Vec::new(),
    };
    let mut out = Vec::new();
    for f in frames(&bytes[HEADER_LEN..]).0 {
        if dec.frame(f, &mut out).is_none() {
            break;
        }
    }
    Ok(out)
}

/// Days with a trace file of `series` (sealed or open), oldest first.
fn list_days(dir: &Path, series: u64) -> std::io::Result<BTreeMap<i64, bool>> {
    let mut days = BTreeMap::new();
    let entries = match std::fs::read_dir(trace_dir(dir, series)) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(days),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else { continue };
        let (stem, sealed) = if let Some(s) = name.strip_suffix(".seg") {
            (s, true)
        } else if let Some(s) = name.strip_suffix(".open") {
            (s, false)
        } else {
            continue;
        };
        if let Some(day) = parse_date(stem) {
            let e = days.entry(day).or_insert(false);
            *e |= sealed;
        }
    }
    Ok(days)
}

/// Sweeps of `series` with `from_ms <= ts_ms < to_ms`, oldest first.
pub fn read_trace(
    dir: &Path,
    series: u64,
    from_ms: i64,
    to_ms: i64,
) -> Result<Vec<TraceRecord>, StoreError> {
    let mut out = Vec::new();
    if from_ms >= to_ms {
        return Ok(out);
    }
    let (first, last) = (day_of(from_ms), day_of(to_ms - 1));
    for (day, sealed) in list_days(dir, series)? {
        if day < first || day > last {
            continue;
        }
        let mut recs = read_day(&day_path(dir, series, day, sealed), series, day)?;
        // A seal finished between listing and reading.
        if recs.is_empty() && !sealed {
            recs = read_day(&day_path(dir, series, day, true), series, day)?;
        }
        out.extend(
            recs.into_iter()
                .filter(|r| (from_ms..to_ms).contains(&r.ts_ms)),
        );
    }
    out.sort_by_key(|r| r.ts_ms);
    Ok(out)
}

/// What [`TraceLog::append`] did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceAppended {
    Stored,
    /// Its day is already sealed, or older than retention keeps.
    Late,
}

/// Counters since the log was opened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TraceStats {
    pub appended: u64,
    pub late: u64,
    pub sealed: u64,
    pub expired_files: u64,
}

#[derive(Debug)]
struct OpenDay {
    file: BufWriter<File>,
    addrs: HashMap<IpAddr, u64>,
}

/// Appends sweeps to the raw trace tier. One per data directory, owned by
/// the process that holds the store's writer.
#[derive(Debug)]
pub struct TraceLog {
    dir: PathBuf,
    keep_days: i64,
    open: BTreeMap<(u64, i64), OpenDay>,
    dirty: BTreeSet<(u64, i64)>,
    dirty_dirs: BTreeSet<PathBuf>,
    /// Series known to have a trace directory.
    known: BTreeSet<u64>,
    /// Seal cutoff of the last maintenance pass.
    maintained_at: Option<i64>,
    stats: TraceStats,
}

impl TraceLog {
    /// `keep_days` whole UTC days are kept besides today.
    pub fn open(dir: &Path, keep_days: i64) -> Result<Self, StoreError> {
        if keep_days < 1 {
            return Err(StoreError::InvalidOptions(
                "trace retention must be at least one day",
            ));
        }
        let mut known = BTreeSet::new();
        if let Ok(entries) = std::fs::read_dir(dir.join("series")) {
            for entry in entries {
                let entry = entry?;
                if let Some(id) = entry.file_name().to_str().and_then(|n| n.parse().ok()) {
                    if entry.path().join("trace").is_dir() {
                        known.insert(id);
                    }
                }
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            keep_days,
            open: BTreeMap::new(),
            dirty: BTreeSet::new(),
            dirty_dirs: BTreeSet::new(),
            known,
            maintained_at: None,
            stats: TraceStats::default(),
        })
    }

    pub fn stats(&self) -> TraceStats {
        self.stats
    }

    /// Buffer one sweep. It is durable after the next [`sync`](Self::sync).
    pub fn append(
        &mut self,
        series: u64,
        rec: &TraceRecord,
        now_ms: i64,
    ) -> Result<TraceAppended, StoreError> {
        let day = day_of(rec.ts_ms);
        if !(layout::MIN_DAY..=layout::MAX_DAY).contains(&day) {
            return Err(StoreError::InvalidRound("sweep time out of range"));
        }
        if rec.hops.len() > 255 {
            return Err(StoreError::InvalidRound("more than 255 hops"));
        }
        let today = day_of(now_ms);
        if day < today.saturating_sub(self.keep_days) || self.sealed_day(series, day, now_ms) {
            self.stats.late += 1;
            return Ok(TraceAppended::Late);
        }
        if !self.open.contains_key(&(series, day)) {
            let od = self.open_day(series, day)?;
            self.open.insert((series, day), od);
        }
        let od = self
            .open
            .get_mut(&(series, day))
            .ok_or_else(|| StoreError::Stopped("trace day vanished".into()))?;
        let mut out = Vec::with_capacity(16 + rec.hops.len() * 6);
        let mut body = Vec::with_capacity(8 + rec.hops.len() * 5);
        let mut index = |addr: IpAddr, out: &mut Vec<u8>| -> u64 {
            let next = od.addrs.len() as u64 + 1;
            *od.addrs.entry(addr).or_insert_with(|| {
                let mut b = Vec::with_capacity(18);
                put_addr(&mut b, addr);
                codec::put_frame(out, &b);
                next
            })
        };
        body.push(TAG_SWEEP);
        varint::put_u64(&mut body, (rec.ts_ms - day * DAY_MS).unsigned_abs());
        body.push(rec.timing.map_or(0, TimingBackend::code));
        varint::put_u64(&mut body, rec.hops.len() as u64);
        for hop in &rec.hops {
            match *hop {
                TraceHop::Lost => body.push(KIND_LOST),
                TraceHop::SendFailed => body.push(KIND_SEND_FAILED),
                TraceHop::TimeExceeded { from, rtt_us } | TraceHop::Reply { from, rtt_us } => {
                    let kind = if matches!(hop, TraceHop::Reply { .. }) {
                        KIND_REPLY
                    } else {
                        KIND_TIME_EXCEEDED
                    };
                    let i = index(from, &mut out);
                    body.push(kind);
                    varint::put_u64(&mut body, i);
                    varint::put_u64(&mut body, units(rtt_us));
                }
                TraceHop::Unreachable { from, code, rtt_us } => {
                    let i = from.map_or(0, |a| index(a, &mut out));
                    body.push(KIND_UNREACHABLE);
                    varint::put_u64(&mut body, i);
                    body.push(code);
                    varint::put_u64(&mut body, units(rtt_us));
                }
            }
        }
        codec::put_frame(&mut out, &body);
        od.file.write_all(&out)?;
        self.dirty.insert((series, day));
        self.stats.appended += 1;
        Ok(TraceAppended::Stored)
    }

    fn sealed_day(&self, series: u64, day: i64, now_ms: i64) -> bool {
        !self.open.contains_key(&(series, day))
            && (day < day_of(now_ms - SEAL_GRACE_MS)
                || day_path(&self.dir, series, day, true).exists())
    }

    /// Open (or create) a day's file, cutting off a torn tail and loading
    /// its address table.
    fn open_day(&mut self, series: u64, day: i64) -> Result<OpenDay, StoreError> {
        let tdir = trace_dir(&self.dir, series);
        if self.known.insert(series) {
            std::fs::create_dir_all(&tdir)?;
            self.dirty_dirs.insert(tdir.clone());
            if let Some(p) = tdir.parent() {
                self.dirty_dirs.insert(p.to_path_buf());
                if let Some(pp) = p.parent() {
                    self.dirty_dirs.insert(pp.to_path_buf());
                }
            }
        }
        let path = day_path(&self.dir, series, day, false);
        let mut addrs = HashMap::new();
        let file = match std::fs::read(&path) {
            Ok(bytes) if bytes.len() >= HEADER_LEN && check_header(&bytes, series, day).is_ok() => {
                let (fs, len) = frames(&bytes[HEADER_LEN..]);
                for f in fs {
                    let mut r = Reader::new(f);
                    if r.byte() == Some(TAG_ADDR) {
                        if let Some(a) = read_addr(&mut r) {
                            let next = addrs.len() as u64 + 1;
                            addrs.insert(a, next);
                        }
                    }
                }
                let f = OpenOptions::new().write(true).open(&path)?;
                f.set_len((HEADER_LEN + len) as u64)?;
                f.sync_all()?;
                let mut f = f;
                std::io::Seek::seek(&mut f, std::io::SeekFrom::End(0))?;
                f
            }
            Ok(_) => {
                // A header torn by a crash right after creating the file.
                let mut f = OpenOptions::new().write(true).truncate(true).open(&path)?;
                f.write_all(&header(series, day))?;
                f.sync_all()?;
                f
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)?;
                f.write_all(&header(series, day))?;
                f.sync_all()?;
                self.dirty_dirs.insert(tdir);
                f
            }
            Err(e) => return Err(e.into()),
        };
        Ok(OpenDay {
            file: BufWriter::with_capacity(64 << 10, file),
            addrs,
        })
    }

    /// Make every buffered sweep durable.
    pub fn sync(&mut self) -> Result<(), StoreError> {
        for key in std::mem::take(&mut self.dirty) {
            if let Some(od) = self.open.get_mut(&key) {
                od.file.flush()?;
                od.file.get_ref().sync_data()?;
            }
        }
        for d in std::mem::take(&mut self.dirty_dirs) {
            layout::sync_dir(&d)?;
        }
        Ok(())
    }

    /// Seal days that ended before `now_ms` (less a grace period) and
    /// delete days older than retention. Cheap when nothing is due.
    pub fn maintain(&mut self, now_ms: i64) -> Result<(), StoreError> {
        let cutoff = day_of(now_ms - SEAL_GRACE_MS);
        if self.maintained_at == Some(cutoff) {
            return Ok(());
        }
        self.sync()?;
        let oldest = day_of(now_ms).saturating_sub(self.keep_days);
        let due: Vec<(u64, i64)> = self
            .open
            .keys()
            .copied()
            .filter(|&(_, d)| d < cutoff)
            .collect();
        for key in due {
            self.open.remove(&key);
        }
        for series in self.known.clone() {
            let tdir = trace_dir(&self.dir, series);
            let mut changed = false;
            for (day, sealed) in list_days(&self.dir, series)? {
                let open = day_path(&self.dir, series, day, false);
                if day < oldest {
                    for p in [day_path(&self.dir, series, day, true), open] {
                        if remove_if_exists(&p)? {
                            self.stats.expired_files += 1;
                        }
                    }
                    changed = true;
                } else if day < cutoff {
                    if sealed {
                        // A seal that stopped before removing the open file.
                        changed |= remove_if_exists(&open)?;
                    } else {
                        self.seal(series, day)?;
                        changed = true;
                    }
                }
            }
            if changed {
                layout::sync_dir(&tdir)?;
            }
        }
        self.maintained_at = Some(cutoff);
        Ok(())
    }

    fn seal(&mut self, series: u64, day: i64) -> Result<(), StoreError> {
        let open = day_path(&self.dir, series, day, false);
        let bytes = std::fs::read(&open)?;
        let mut out = header(series, day);
        if check_header(&bytes, series, day).is_ok() {
            let body = &bytes[HEADER_LEN..];
            let (fs, _) = frames(body);
            let mut chunk = Vec::with_capacity(BLOCK_BYTES + 4096);
            let flush = |chunk: &mut Vec<u8>, out: &mut Vec<u8>| -> Result<(), StoreError> {
                if chunk.is_empty() {
                    return Ok(());
                }
                let z = zstd::bulk::compress(chunk, ZSTD_LEVEL)?;
                let mut b = Vec::with_capacity(z.len() + 1);
                b.push(TAG_BLOCK);
                b.extend_from_slice(&z);
                codec::put_frame(out, &b);
                chunk.clear();
                Ok(())
            };
            for f in fs {
                codec::put_frame(&mut chunk, f);
                if chunk.len() >= BLOCK_BYTES {
                    flush(&mut chunk, &mut out)?;
                }
            }
            flush(&mut chunk, &mut out)?;
        }
        let sealed = day_path(&self.dir, series, day, true);
        let tmp = sealed.with_extension("seg.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&out)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &sealed)?;
        layout::sync_dir(&trace_dir(&self.dir, series))?;
        std::fs::remove_file(&open)?;
        self.stats.sealed += 1;
        Ok(())
    }

    /// Sync and close every open day.
    pub fn close(mut self) -> Result<(), StoreError> {
        self.sync()
    }
}

fn remove_if_exists(p: &Path) -> Result<bool, StoreError> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 20_000;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    fn rec(ts_ms: i64, hops: Vec<TraceHop>) -> TraceRecord {
        TraceRecord {
            ts_ms,
            timing: Some(TimingBackend::LinuxKernelTimestamp),
            hops,
        }
    }

    fn sample(ts_ms: i64) -> TraceRecord {
        rec(
            ts_ms,
            vec![
                TraceHop::TimeExceeded {
                    from: ip(1),
                    rtt_us: 1_234,
                },
                TraceHop::Lost,
                TraceHop::SendFailed,
                TraceHop::Unreachable {
                    from: None,
                    code: 3,
                    rtt_us: 50,
                },
                TraceHop::Reply {
                    from: "2001:db8::10".parse().unwrap(),
                    rtt_us: 9_990,
                },
            ],
        )
    }

    #[test]
    fn sweeps_round_trip_open_and_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let t0 = DAY * DAY_MS + 1_000;
        let mut log = TraceLog::open(dir.path(), 7).unwrap();
        log.append(7, &sample(t0 + 2_500), t0).unwrap();
        log.append(7, &sample(t0), t0).unwrap();
        log.sync().unwrap();
        let mut want = vec![sample(t0), sample(t0 + 2_500)];
        // 1,234 µs is kept as 1,230.
        for r in &mut want {
            r.hops[0] = TraceHop::TimeExceeded {
                from: ip(1),
                rtt_us: 1_230,
            };
        }
        assert_eq!(read_trace(dir.path(), 7, t0, t0 + 3_000).unwrap(), want);
        // The next day, past the grace period: sealed, same records.
        log.maintain(t0 + DAY_MS + SEAL_GRACE_MS).unwrap();
        assert!(day_path(dir.path(), 7, DAY, true).exists());
        assert!(!day_path(dir.path(), 7, DAY, false).exists());
        assert_eq!(read_trace(dir.path(), 7, t0, t0 + 3_000).unwrap(), want);
        // A sweep for the sealed day is late.
        assert_eq!(
            log.append(7, &sample(t0 + 5_000), t0 + DAY_MS + SEAL_GRACE_MS)
                .unwrap(),
            TraceAppended::Late
        );
    }

    #[test]
    fn a_torn_tail_is_cut_off_and_appends_continue() {
        let dir = tempfile::tempdir().unwrap();
        let t0 = DAY * DAY_MS;
        {
            let mut log = TraceLog::open(dir.path(), 7).unwrap();
            log.append(1, &sample(t0), t0).unwrap();
            log.append(1, &sample(t0 + 1), t0).unwrap();
            log.close().unwrap();
        }
        let path = day_path(dir.path(), 1, DAY, false);
        let len = std::fs::metadata(&path).unwrap().len();
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 3).unwrap();
        drop(f);
        let mut log = TraceLog::open(dir.path(), 7).unwrap();
        log.append(1, &sample(t0 + 2), t0).unwrap();
        log.close().unwrap();
        let got: Vec<i64> = read_trace(dir.path(), 1, t0, t0 + 10)
            .unwrap()
            .iter()
            .map(|r| r.ts_ms)
            .collect();
        assert_eq!(got, vec![t0, t0 + 2]);
    }

    #[test]
    fn retention_deletes_whole_days() {
        let dir = tempfile::tempdir().unwrap();
        let t0 = DAY * DAY_MS;
        let mut log = TraceLog::open(dir.path(), 7).unwrap();
        for d in 0..10 {
            log.append(3, &sample(t0 + d * DAY_MS), t0 + d * DAY_MS)
                .unwrap();
            log.maintain(t0 + d * DAY_MS + SEAL_GRACE_MS).unwrap();
        }
        let days: Vec<i64> = list_days(dir.path(), 3).unwrap().into_keys().collect();
        // Today (DAY + 9) and the 7 days before it.
        assert_eq!(days, ((DAY + 2)..=(DAY + 9)).collect::<Vec<_>>());
        assert_eq!(log.stats().expired_files, 2);
    }

    #[test]
    fn a_15_hop_day_at_2_5_s_fits_in_2_mb() {
        let dir = tempfile::tempdir().unwrap();
        let t0 = DAY * DAY_MS;
        let mut log = TraceLog::open(dir.path(), 7).unwrap();
        let mut seed = 0x1234_5678_u32;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for i in 0..34_560 {
            let hops = (1..=15u8)
                .map(|ttl| {
                    let rtt_us = u32::from(ttl) * 2_000 + rnd() % 3_000;
                    if rnd() % 100 < 3 {
                        TraceHop::Lost
                    } else if ttl == 15 {
                        TraceHop::Reply {
                            from: ip(100),
                            rtt_us,
                        }
                    } else {
                        // Some ECMP at hop 5.
                        let from = if ttl == 5 && rnd() % 2 == 0 {
                            ip(55)
                        } else {
                            ip(ttl)
                        };
                        TraceHop::TimeExceeded { from, rtt_us }
                    }
                })
                .collect();
            log.append(9, &rec(t0 + i * 2_500, hops), t0).unwrap();
        }
        log.maintain(t0 + DAY_MS + SEAL_GRACE_MS).unwrap();
        let size = std::fs::metadata(day_path(dir.path(), 9, DAY, true))
            .unwrap()
            .len();
        eprintln!("sealed 15-hop day: {size} bytes");
        assert!(size <= 2 << 20, "sealed day is {size} bytes");
        assert_eq!(
            read_trace(dir.path(), 9, t0, t0 + DAY_MS).unwrap().len(),
            34_560
        );
    }
}
