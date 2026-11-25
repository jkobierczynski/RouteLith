//! The agent's spool (§21.7 G8): every round is written to
//! `data_dir/spool/` before it is sent, and deleted once the server has
//! acknowledged it, so neither a link outage nor an agent restart loses
//! rounds.
//!
//! ```text
//! spool/id                       random spool id (hex), made once
//! spool/state                    "<acked seq> <next seq>"
//! spool/00000000000000000001.seg rounds from seq 1 on
//! ```
//!
//! A segment is a magic line followed by frames of
//! `len: u32 LE | crc32c(body): u32 LE | body` where the body is a
//! protobuf `Round`. Seqs within a segment are consecutive. Only the newest
//! segment is written to; it is closed at [`SEGMENT_MAX_BYTES`] or after an
//! hour. A torn frame at the end (a crash mid-write) is cut off when the
//! spool is opened.
//!
//! The spool is bounded by size and age; when either is exceeded the
//! oldest segments are dropped, acknowledged or not, and the rounds lost
//! are counted.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use prost::Message;

use crate::{FedError, files, pb};

/// Default bound on the spool's size.
pub const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;
/// Default bound on the age of spooled rounds.
pub const DEFAULT_MAX_AGE_MS: i64 = 30 * 86_400_000;
/// A segment is closed when it reaches this size (or a sixteenth of the
/// spool's bound, if smaller).
pub const SEGMENT_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// … or when it is this old.
pub const SEGMENT_MAX_AGE_MS: i64 = 3_600_000;

const MAGIC: &[u8; 8] = b"RLSPOOL1";
const FRAME_HEAD: usize = 8;
/// Longest body accepted when reading (a round is far smaller).
const MAX_BODY: usize = 16 * 1024 * 1024;

/// `data_dir/spool`.
pub fn spool_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("spool")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_age_ms: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_bytes: DEFAULT_MAX_BYTES,
            max_age_ms: DEFAULT_MAX_AGE_MS,
        }
    }
}

#[derive(Debug)]
struct Segment {
    path: PathBuf,
    first_seq: u64,
    /// `first_seq - 1` while empty.
    last_seq: u64,
    bytes: u64,
    created_ms: i64,
    /// Newest round start in it.
    newest_ts_ms: i64,
}

impl Segment {
    fn rounds(&self) -> u64 {
        self.last_seq + 1 - self.first_seq
    }
}

/// Where the next read continues, to avoid rescanning a segment.
#[derive(Debug, Clone)]
struct Cursor {
    first_seq: u64,
    offset: u64,
    next_seq: u64,
}

/// Rounds dropped by the spool's bounds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dropped {
    pub rounds: u64,
    pub segments: u64,
}

#[derive(Debug)]
pub struct Spool {
    dir: PathBuf,
    id: u64,
    limits: Limits,
    acked: u64,
    next_seq: u64,
    segments: VecDeque<Segment>,
    /// The newest segment, open for appending.
    active: Option<File>,
    /// Bytes appended since the last sync.
    dirty: bool,
    cursor: Option<Cursor>,
    /// Since the spool was opened.
    dropped: Dropped,
}

/// What opening the spool found.
#[derive(Debug, Default)]
pub struct Opened {
    /// Damage repaired or skipped, for the log.
    pub notes: Vec<String>,
}

fn io(what: String) -> impl FnOnce(std::io::Error) -> FedError {
    move |e| FedError::Io(what, e)
}

fn seg_name(first_seq: u64) -> String {
    format!("{first_seq:020}.seg")
}

impl Spool {
    /// Open (or create) the spool in `dir`.
    pub fn open(dir: &Path, limits: Limits, now_ms: i64) -> Result<(Spool, Opened), FedError> {
        std::fs::create_dir_all(dir).map_err(io(format!("cannot create {}", dir.display())))?;
        let mut opened = Opened::default();
        let id = match files::read_optional(&dir.join("id"))? {
            Some(b) => {
                let text = String::from_utf8_lossy(&b);
                u64::from_str_radix(text.trim(), 16).map_err(|_| {
                    FedError::Invalid(format!("{}: not a spool id", dir.join("id").display()))
                })?
            }
            None => {
                let id = random_id()?;
                files::write_private(&dir.join("id"), format!("{id:016x}\n").as_bytes())?;
                id
            }
        };
        let (mut acked, mut next_seq) = (0u64, 1u64);
        if let Some(b) = files::read_optional(&dir.join("state"))? {
            let text = String::from_utf8_lossy(&b);
            let mut parts = text.split_whitespace().map(str::parse::<u64>);
            match (parts.next(), parts.next()) {
                (Some(Ok(a)), Some(Ok(n))) if n > a => (acked, next_seq) = (a, n),
                _ => opened.notes.push(format!(
                    "{}: unreadable, ignored",
                    dir.join("state").display()
                )),
            }
        }
        let mut names: Vec<(u64, PathBuf)> = Vec::new();
        let entries =
            std::fs::read_dir(dir).map_err(io(format!("cannot list {}", dir.display())))?;
        for entry in entries {
            let entry = entry.map_err(io(format!("cannot list {}", dir.display())))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(stem) = name.strip_suffix(".seg") else {
                continue;
            };
            if let Ok(first) = stem.parse::<u64>() {
                if first > 0 {
                    names.push((first, entry.path()));
                }
            }
        }
        names.sort();
        let mut segments = VecDeque::new();
        let count = names.len();
        for (i, (first_seq, path)) in names.into_iter().enumerate() {
            let last = i + 1 == count;
            let seg = scan(&path, first_seq, now_ms, last, &mut opened.notes)?;
            let Some(seg) = seg else { continue };
            // Overlapping seqs can only come from damage: keep the older.
            if segments
                .back()
                .is_some_and(|p: &Segment| seg.first_seq <= p.last_seq)
            {
                opened.notes.push(format!(
                    "{}: overlaps the segment before it, ignored",
                    path.display()
                ));
                continue;
            }
            segments.push_back(seg);
        }
        if let Some(s) = segments.back() {
            next_seq = next_seq.max(s.last_seq + 1);
        }
        next_seq = next_seq.max(acked + 1);
        let mut spool = Spool {
            dir: dir.to_path_buf(),
            id,
            limits,
            acked,
            next_seq,
            segments,
            active: None,
            dirty: false,
            cursor: None,
            dropped: Dropped::default(),
        };
        spool.forget_acked()?;
        Ok((spool, opened))
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// Highest acknowledged seq.
    pub fn acked(&self) -> u64 {
        self.acked
    }

    /// Highest seq written (0 if none ever).
    pub fn last_seq(&self) -> u64 {
        self.next_seq - 1
    }

    /// Rounds written and not acknowledged (some may have been dropped).
    pub fn backlog(&self) -> u64 {
        self.last_seq().saturating_sub(self.acked)
    }

    pub fn bytes(&self) -> u64 {
        self.segments.iter().map(|s| s.bytes).sum()
    }

    pub fn dropped(&self) -> Dropped {
        self.dropped
    }

    fn segment_max(&self) -> u64 {
        SEGMENT_MAX_BYTES.min(self.limits.max_bytes / 16).max(4096)
    }

    /// Write a round, giving it the next seq. Durable after [`sync`](Self::sync).
    pub fn push(&mut self, mut round: pb::Round, now_ms: i64) -> Result<u64, FedError> {
        let seq = self.next_seq;
        round.seq = seq;
        let body = round.encode_to_vec();
        let mut frame = Vec::with_capacity(FRAME_HEAD + body.len());
        frame.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes());
        frame.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes());
        frame.extend_from_slice(&body);

        let rotate = match self.segments.back() {
            None => true,
            Some(s) => {
                s.bytes >= self.segment_max()
                    || (s.rounds() > 0 && now_ms.saturating_sub(s.created_ms) >= SEGMENT_MAX_AGE_MS)
                    // A segment left over from before a restart is not
                    // appended to: start a fresh one.
                    || self.active.is_none()
            }
        };
        if rotate {
            self.start_segment(seq, now_ms)?;
        }
        let Some((seg, file)) = self.segments.back_mut().zip(self.active.as_mut()) else {
            return Err(FedError::Invalid("spool has no open segment".into()));
        };
        if let Err(e) = file.write_all(&frame) {
            // A partial frame would hide every later one: cut it off and
            // start a new segment next time.
            let _ = file.set_len(seg.bytes);
            self.active = None;
            return Err(FedError::Io(
                format!("cannot write {}", seg.path.display()),
                e,
            ));
        }
        seg.bytes += frame.len() as u64;
        seg.last_seq = seq;
        seg.newest_ts_ms = seg.newest_ts_ms.max(round.ts_ms);
        self.next_seq = seq + 1;
        self.dirty = true;
        self.enforce(now_ms)?;
        Ok(seq)
    }

    fn start_segment(&mut self, first_seq: u64, now_ms: i64) -> Result<(), FedError> {
        self.sync()?;
        // An empty segment left over is replaced by the new one.
        if self.segments.back().is_some_and(|s| s.rounds() == 0) {
            if let Some(s) = self.segments.pop_back() {
                let _ = std::fs::remove_file(&s.path);
            }
        }
        let path = self.dir.join(seg_name(first_seq));
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(io(format!("cannot create {}", path.display())))?;
        f.write_all(MAGIC)
            .map_err(io(format!("cannot write {}", path.display())))?;
        files::sync_dir(&self.dir);
        self.active = Some(f);
        self.segments.push_back(Segment {
            path,
            first_seq,
            last_seq: first_seq - 1,
            bytes: MAGIC.len() as u64,
            created_ms: now_ms,
            newest_ts_ms: i64::MIN,
        });
        Ok(())
    }

    /// Make every pushed round durable.
    pub fn sync(&mut self) -> Result<(), FedError> {
        if let (true, Some(f)) = (self.dirty, &self.active) {
            f.sync_data()
                .map_err(io("cannot sync the spool".to_string()))?;
        }
        self.dirty = false;
        Ok(())
    }

    /// The server has stored every round up to `seq`.
    pub fn ack(&mut self, seq: u64) -> Result<(), FedError> {
        let seq = seq.min(self.last_seq());
        if seq <= self.acked {
            return Ok(());
        }
        self.acked = seq;
        self.forget_acked()?;
        self.save_state()
    }

    /// Never hand out a seq at or below `seq` again (the server has stored
    /// that far, from a spool state this one lost).
    pub fn skip_past(&mut self, seq: u64) -> Result<(), FedError> {
        if seq < self.next_seq {
            return Ok(());
        }
        self.next_seq = seq + 1;
        self.acked = self.acked.max(seq);
        // Rounds spooled under the reused seqs would be refused as
        // replays: they are lost either way.
        self.active = None;
        self.save_state()
    }

    fn save_state(&self) -> Result<(), FedError> {
        files::write_private(
            &self.dir.join("state"),
            format!("{} {}\n", self.acked, self.next_seq).as_bytes(),
        )
    }

    /// Delete segments whose every round is acknowledged, except the one
    /// being written.
    fn forget_acked(&mut self) -> Result<(), FedError> {
        while self.segments.len() > 1 || (self.active.is_none() && !self.segments.is_empty()) {
            let Some(s) = self.segments.front() else {
                break;
            };
            if s.last_seq > self.acked {
                break;
            }
            if self.segments.len() == 1 {
                self.active = None;
            }
            let path = s.path.clone();
            std::fs::remove_file(&path).map_err(io(format!("cannot delete {}", path.display())))?;
            self.segments.pop_front();
        }
        Ok(())
    }

    /// Apply the size and age bounds.
    pub fn enforce(&mut self, now_ms: i64) -> Result<(), FedError> {
        let oldest_ok = now_ms.saturating_sub(self.limits.max_age_ms);
        let mut dropped_any = false;
        loop {
            let over_size = self.bytes() > self.limits.max_bytes;
            let Some(front) = self.segments.front() else {
                break;
            };
            let too_old = front.rounds() > 0 && front.newest_ts_ms < oldest_ok;
            if !over_size && !too_old {
                break;
            }
            if self.segments.len() == 1 {
                if !too_old && front.bytes <= self.segment_max() {
                    // The one segment being written is within bounds by
                    // itself (a tiny limit): nothing to drop.
                    break;
                }
                // Close the only segment so it can go.
                self.active = None;
            }
            let Some(s) = self.segments.pop_front() else {
                break;
            };
            let lost = s.last_seq.saturating_sub(self.acked.max(s.first_seq - 1));
            self.dropped.rounds += lost;
            self.dropped.segments += 1;
            dropped_any = true;
            std::fs::remove_file(&s.path)
                .map_err(io(format!("cannot delete {}", s.path.display())))?;
        }
        if dropped_any {
            self.save_state()?;
        }
        Ok(())
    }

    /// Up to `max` rounds after `after_seq`, in seq order, stopping once
    /// they reach `max_bytes` encoded (at least one is returned). Rounds
    /// dropped by the bounds are skipped.
    pub fn read_after(
        &mut self,
        after_seq: u64,
        max: usize,
        max_bytes: usize,
    ) -> Result<Vec<pb::Round>, FedError> {
        let mut out = Vec::new();
        let mut bytes = 0usize;
        let mut want = after_seq + 1;
        while out.len() < max && bytes < max_bytes && want < self.next_seq {
            let Some(idx) = self.segments.iter().position(|s| s.last_seq >= want) else {
                break;
            };
            let seg = &self.segments[idx];
            if seg.rounds() == 0 {
                break;
            }
            want = want.max(seg.first_seq);
            let start = match &self.cursor {
                Some(c) if c.first_seq == seg.first_seq && c.next_seq <= want => {
                    (c.offset, c.next_seq)
                }
                _ => (MAGIC.len() as u64, seg.first_seq),
            };
            let room = (max - out.len(), max_bytes - bytes);
            let (rounds, cursor, read) = read_segment(seg, start, want, room)?;
            bytes += read;
            let got_any = !rounds.is_empty();
            if let Some(r) = rounds.last() {
                want = r.seq + 1;
            }
            out.extend(rounds);
            self.cursor = Some(cursor);
            if !got_any {
                // Damage in the middle: skip the rest of this segment.
                want = seg.last_seq + 1;
            }
        }
        Ok(out)
    }
}

/// Read a segment from `(offset, seq)`, returning rounds from `want` on
/// (at most `max`, stopping once they reach `max_bytes`), where the next
/// read continues, and the bytes of the rounds returned.
fn read_segment(
    seg: &Segment,
    (offset, mut seq): (u64, u64),
    want: u64,
    (max, max_bytes): (usize, usize),
) -> Result<(Vec<pb::Round>, Cursor, usize), FedError> {
    let mut f = File::open(&seg.path).map_err(io(format!("cannot read {}", seg.path.display())))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(io(format!("cannot read {}", seg.path.display())))?;
    let mut r = std::io::BufReader::with_capacity(256 * 1024, f.take(seg.bytes - offset));
    let mut pos = offset;
    let mut out = Vec::new();
    let mut bytes = 0usize;
    while out.len() < max && bytes < max_bytes && seq <= seg.last_seq {
        let Some(body) = read_frame(&mut r) else {
            break;
        };
        pos += (FRAME_HEAD + body.len()) as u64;
        let Ok(round) = pb::Round::decode(body.as_slice()) else {
            break;
        };
        if round.seq != seq {
            break;
        }
        seq += 1;
        if round.seq >= want {
            bytes += body.len();
            out.push(round);
        }
    }
    Ok((
        out,
        Cursor {
            first_seq: seg.first_seq,
            offset: pos,
            next_seq: seq,
        },
        bytes,
    ))
}

/// One frame's body, `None` at the end or at damage.
fn read_frame(r: &mut impl Read) -> Option<Vec<u8>> {
    let mut head = [0u8; FRAME_HEAD];
    r.read_exact(&mut head).ok()?;
    let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let crc = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    if len > MAX_BODY {
        return None;
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).ok()?;
    (crc32c::crc32c(&body) == crc).then_some(body)
}

/// Check a segment file: its frames must be whole, with good CRCs and
/// consecutive seqs. The newest segment's damaged tail is cut off; an
/// older one keeps its good part. `None` for a file with no rounds, which
/// is deleted.
fn scan(
    path: &Path,
    first_seq: u64,
    now_ms: i64,
    newest: bool,
    notes: &mut Vec<String>,
) -> Result<Option<Segment>, FedError> {
    let bytes = std::fs::read(path).map_err(io(format!("cannot read {}", path.display())))?;
    let mut good = 0usize;
    let mut seq = first_seq;
    let mut newest_ts = i64::MIN;
    if bytes.starts_with(MAGIC) {
        good = MAGIC.len();
        let mut r = &bytes[good..];
        while let Some(body) = read_frame(&mut r) {
            let Ok(round) = pb::Round::decode(body.as_slice()) else {
                break;
            };
            if round.seq != seq {
                break;
            }
            newest_ts = newest_ts.max(round.ts_ms);
            seq += 1;
            good += FRAME_HEAD + body.len();
        }
    }
    if seq == first_seq {
        let _ = std::fs::remove_file(path);
        return Ok(None);
    }
    if good < bytes.len() {
        notes.push(format!(
            "{}: {} damaged byte(s) at the end {}",
            path.display(),
            bytes.len() - good,
            if newest { "cut off" } else { "skipped" }
        ));
        if newest {
            let f = OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(io(format!("cannot repair {}", path.display())))?;
            f.set_len(good as u64)
                .and_then(|()| f.sync_all())
                .map_err(io(format!("cannot repair {}", path.display())))?;
        }
    }
    // Its age counts from now: the file's own time is not trusted.
    Ok(Some(Segment {
        path: path.to_path_buf(),
        first_seq,
        last_seq: seq - 1,
        bytes: good as u64,
        created_ms: now_ms,
        newest_ts_ms: newest_ts,
    }))
}

fn random_id() -> Result<u64, FedError> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| FedError::Invalid("no random numbers from the system".into()))?;
    // Never 0: that is what agents without a spool send.
    Ok(u64::from_le_bytes(b).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round(ts_ms: i64) -> pb::Round {
        pb::Round {
            series_id: 7,
            ts_ms,
            sent: 20,
            rtts_us: vec![1000; 20],
            ..Default::default()
        }
    }

    fn open(dir: &Path, limits: Limits) -> Spool {
        Spool::open(dir, limits, 0).expect("open").0
    }

    fn seqs(v: &[pb::Round]) -> Vec<u64> {
        v.iter().map(|r| r.seq).collect()
    }

    #[test]
    fn rounds_survive_a_restart_and_acked_ones_go() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("spool");
        let mut s = open(&dir, Limits::default());
        let id = s.id();
        for i in 0..10 {
            assert_eq!(s.push(round(i), 0).unwrap(), i as u64 + 1);
        }
        s.sync().unwrap();
        s.ack(4).unwrap();
        drop(s);
        let mut s = open(&dir, Limits::default());
        assert_eq!(s.id(), id);
        assert_eq!((s.acked(), s.last_seq(), s.backlog()), (4, 10, 6));
        assert_eq!(
            seqs(&s.read_after(4, 100, usize::MAX).unwrap()),
            [5, 6, 7, 8, 9, 10]
        );
        assert_eq!(s.push(round(10), 0).unwrap(), 11);
        assert_eq!(seqs(&s.read_after(9, 100, usize::MAX).unwrap()), [10, 11]);
        s.ack(11).unwrap();
        drop(s);
        let s = open(&dir, Limits::default());
        assert_eq!((s.acked(), s.last_seq(), s.backlog()), (11, 11, 0));
        assert_eq!(s.segments.len(), 0, "every segment was acknowledged");
    }

    #[test]
    fn reads_continue_across_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let limits = Limits {
            max_bytes: 1 << 30,
            max_age_ms: DEFAULT_MAX_AGE_MS,
        };
        let mut s = open(tmp.path(), limits);
        // Force small segments: one per hour of pushes.
        for i in 0..50 {
            s.push(round(i), i * SEGMENT_MAX_AGE_MS / 10).unwrap();
        }
        assert!(s.segments.len() >= 4, "{} segments", s.segments.len());
        let mut got = Vec::new();
        let mut after = 0;
        loop {
            let batch = s.read_after(after, 7, usize::MAX).unwrap();
            let Some(last) = batch.last() else { break };
            after = last.seq;
            got.extend(seqs(&batch));
        }
        assert_eq!(got, (1..=50).collect::<Vec<_>>());
        // A read from the middle again (after a reconnect).
        assert_eq!(
            seqs(&s.read_after(22, 3, usize::MAX).unwrap()),
            [23, 24, 25]
        );
        // A byte bound still returns at least one round.
        assert_eq!(seqs(&s.read_after(22, 100, 1).unwrap()), [23]);
    }

    #[test]
    fn a_torn_tail_is_cut_off() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = open(tmp.path(), Limits::default());
        for i in 0..5 {
            s.push(round(i), 0).unwrap();
        }
        s.sync().unwrap();
        let path = s.segments.back().unwrap().path.clone();
        drop(s);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[9, 0, 0, 0, 1, 2]).unwrap();
        drop(f);
        let (mut s, opened) = Spool::open(tmp.path(), Limits::default(), 0).unwrap();
        assert_eq!(opened.notes.len(), 1, "{:?}", opened.notes);
        assert_eq!(s.last_seq(), 5);
        s.push(round(5), 0).unwrap();
        assert_eq!(
            seqs(&s.read_after(0, 100, usize::MAX).unwrap()),
            [1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn a_full_spool_drops_the_oldest_and_counts_them() {
        let tmp = tempfile::tempdir().unwrap();
        let limits = Limits {
            max_bytes: 64 * 1024,
            max_age_ms: DEFAULT_MAX_AGE_MS,
        };
        let mut s = open(tmp.path(), limits);
        for i in 0..2000 {
            s.push(round(i), 0).unwrap();
        }
        assert!(s.bytes() <= limits.max_bytes, "{} bytes", s.bytes());
        let d = s.dropped();
        assert!(d.rounds > 0 && d.segments > 0, "{d:?}");
        let left = s.read_after(0, 10_000, usize::MAX).unwrap();
        assert_eq!(left.len() as u64 + d.rounds, 2000);
        assert_eq!(left.last().unwrap().seq, 2000);
        drop(s);
        // Seqs carry on after a restart even though the oldest are gone.
        let mut s = open(tmp.path(), limits);
        assert_eq!(s.push(round(2000), 0).unwrap(), 2001);
    }

    #[test]
    fn old_rounds_are_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let limits = Limits {
            max_bytes: DEFAULT_MAX_BYTES,
            max_age_ms: 10 * SEGMENT_MAX_AGE_MS,
        };
        let mut s = open(tmp.path(), limits);
        let hour = SEGMENT_MAX_AGE_MS;
        for h in 0..20 {
            s.push(round(h * hour), h * hour).unwrap();
        }
        s.enforce(20 * hour).unwrap();
        let left = seqs(&s.read_after(0, 100, usize::MAX).unwrap());
        assert_eq!(left.first(), Some(&11), "{left:?}");
        assert_eq!(s.dropped().rounds, 10);
    }

    #[test]
    fn skip_past_moves_seqs_on() {
        let tmp = tempfile::tempdir().unwrap();
        let mut s = open(tmp.path(), Limits::default());
        s.push(round(0), 0).unwrap();
        s.skip_past(100).unwrap();
        assert_eq!(s.push(round(1), 0).unwrap(), 101);
        assert_eq!(seqs(&s.read_after(100, 10, usize::MAX).unwrap()), [101]);
        drop(s);
        let s = open(tmp.path(), Limits::default());
        assert_eq!(s.last_seq(), 101);
    }
}
