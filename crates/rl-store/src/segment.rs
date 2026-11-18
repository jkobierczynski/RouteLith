//! Day segments: a fixed header followed by CRC-framed blocks.
//!
//! Header: `b"RLSEG\0\0\x01" | series: u64 LE | day: i64 LE | crc32c: u32 LE`.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

use crate::codec::{self, BlockHeader, Frame};
use crate::round::StoredRound;

const MAGIC: &[u8; 8] = b"RLSEG\0\0\x01";
pub(crate) const HEADER_LEN: usize = 8 + 8 + 8 + 4;

pub(crate) fn header(series: u64, day: i64) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(MAGIC);
    h.extend_from_slice(&series.to_le_bytes());
    h.extend_from_slice(&day.to_le_bytes());
    let crc = crc32c::crc32c(&h);
    h.extend_from_slice(&crc.to_le_bytes());
    h
}

/// How a segment file ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tail {
    /// Every byte belongs to a valid block.
    Clean,
    /// The file ends inside a block: a write cut short by a crash.
    Torn,
    /// A block has a bad length or checksum.
    Corrupt,
}

/// Result of reading a segment file's structure.
#[derive(Debug, Clone)]
pub(crate) struct Scan {
    pub(crate) series: u64,
    pub(crate) day: i64,
    /// Blocks with a valid checksum: (offset of the frame, header).
    pub(crate) blocks: Vec<(usize, BlockHeader)>,
    /// Bytes up to the end of the last valid block.
    pub(crate) valid_len: u64,
    pub(crate) tail: Tail,
}

impl Scan {
    pub(crate) fn last_ts(&self) -> Option<i64> {
        self.blocks.last().map(|(_, h)| h.last_ts)
    }
}

/// Read the header and every block frame of a segment held in memory.
/// `Err` if the header itself is missing or wrong.
pub(crate) fn scan(bytes: &[u8]) -> Result<Scan, &'static str> {
    let h = bytes
        .get(..HEADER_LEN)
        .ok_or("segment header is truncated")?;
    if &h[..8] != MAGIC {
        return Err("not a segment file (bad magic)");
    }
    let crc = u32::from_le_bytes(h[24..28].try_into().map_err(|_| "header")?);
    if crc32c::crc32c(&h[..24]) != crc {
        return Err("segment header checksum mismatch");
    }
    let series = u64::from_le_bytes(h[8..16].try_into().map_err(|_| "header")?);
    let day = i64::from_le_bytes(h[16..24].try_into().map_err(|_| "header")?);
    let mut pos = HEADER_LEN;
    let mut blocks = Vec::new();
    let tail = loop {
        if pos == bytes.len() {
            break Tail::Clean;
        }
        match codec::read_frame(&bytes[pos..]) {
            Frame::Ok(body, len) => {
                let Some(bh) = codec::block_header(body) else {
                    break Tail::Corrupt;
                };
                blocks.push((pos, bh));
                pos += len;
            }
            Frame::Truncated => break Tail::Torn,
            Frame::Corrupt => break Tail::Corrupt,
        }
    };
    Ok(Scan {
        series,
        day,
        blocks,
        valid_len: pos as u64,
        tail,
    })
}

/// Rounds in `[from_ms, to_ms]` from the valid blocks of a segment.
/// Blocks outside the range are skipped without decompressing them.
pub(crate) fn read_range(
    bytes: &[u8],
    scan: &Scan,
    from_ms: i64,
    to_ms: i64,
) -> Result<Vec<StoredRound>, &'static str> {
    let mut out = Vec::new();
    for &(offset, h) in &scan.blocks {
        if h.last_ts < from_ms || h.first_ts > to_ms {
            continue;
        }
        let Frame::Ok(body, _) = codec::read_frame(&bytes[offset..]) else {
            return Err("block changed while reading");
        };
        let rounds = codec::decode_block(body).ok_or("block does not decode")?;
        out.extend(
            rounds
                .into_iter()
                .filter(|r| (from_ms..=to_ms).contains(&r.ts_ms)),
        );
    }
    Ok(out)
}

/// Create a new open segment with just its header.
pub(crate) fn create(path: &Path, series: u64, day: i64) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(e) = f.write_all(&header(series, day)) {
        // Created by this call: remove it so a retry can create it again.
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// Append one block frame. The caller decides when to `fsync`.
pub(crate) fn append_block(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(codec::FRAME_HEADER + body.len());
    codec::put_frame(&mut frame, body);
    let mut f = OpenOptions::new().append(true).open(path)?;
    let len = f.metadata()?.len();
    if let Err(e) = f.write_all(&frame) {
        // Don't leave half a frame for the next block to follow. If this
        // fails too, the writer stops and recovery trims the tail. A new
        // handle: on Windows an append-only one may not truncate.
        drop(f);
        let undo = OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|f| f.set_len(len));
        if let Err(undo) = undo {
            return Err(io::Error::new(
                e.kind(),
                format!("{e}; removing the partial block also failed: {undo}"),
            ));
        }
        return Err(e);
    }
    Ok(())
}

/// Cut a torn or corrupt tail so the file ends on a valid block.
pub(crate) fn truncate(path: &Path, len: u64) -> io::Result<()> {
    let f = OpenOptions::new().write(true).open(path)?;
    f.set_len(len)?;
    f.sync_all()
}

/// `fsync` a file by path. Opened for writing: Windows refuses to flush a
/// read-only handle.
pub(crate) fn sync(path: &Path) -> io::Result<()> {
    OpenOptions::new().write(true).open(path)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::round::ErrorCounts;

    fn round(ts_ms: i64) -> StoredRound {
        StoredRound {
            ts_ms,
            sent: 2,
            rtts_us: vec![100, 200],
            errors: ErrorCounts::default(),
            resolved: None,
            timing: None,
            flags: 0,
        }
    }

    fn segment(blocks: &[&[i64]]) -> Vec<u8> {
        let mut bytes = header(7, 3);
        for b in blocks {
            let rounds: Vec<_> = b.iter().map(|&t| round(t)).collect();
            codec::put_frame(&mut bytes, &codec::encode_block(&rounds, 3));
        }
        bytes
    }

    #[test]
    fn scan_and_range_read() {
        let bytes = segment(&[&[10, 20], &[30, 40]]);
        let s = scan(&bytes).unwrap();
        assert_eq!((s.series, s.day, s.blocks.len()), (7, 3, 2));
        assert_eq!(s.tail, Tail::Clean);
        assert_eq!(s.last_ts(), Some(40));
        let ts: Vec<_> = read_range(&bytes, &s, 20, 30)
            .unwrap()
            .iter()
            .map(|r| r.ts_ms)
            .collect();
        assert_eq!(ts, [20, 30]);
    }

    #[test]
    fn torn_tail_keeps_complete_blocks() {
        let full = segment(&[&[10], &[20]]);
        let torn = &full[..full.len() - 3];
        let s = scan(torn).unwrap();
        assert_eq!(s.tail, Tail::Torn);
        assert_eq!(s.blocks.len(), 1);
        assert_eq!(s.last_ts(), Some(10));
    }

    #[test]
    fn corrupt_block_stops_the_scan() {
        let mut bytes = segment(&[&[10], &[20]]);
        let n = bytes.len();
        bytes[n - 1] ^= 0xff;
        let s = scan(&bytes).unwrap();
        assert_eq!(s.tail, Tail::Corrupt);
        assert_eq!(s.blocks.len(), 1);
    }

    #[test]
    fn bad_header_is_an_error() {
        let mut bytes = segment(&[]);
        bytes[9] ^= 1;
        assert!(scan(&bytes).is_err());
        assert!(scan(b"RLSEG").is_err());
    }
}
