//! Write-ahead log: every round is appended here before it reaches a block.
//!
//! Header: `b"RLWAL\0\0\x01" | seq: u64 LE | crc32c: u32 LE`, then one frame
//! per round with body `series: u64 LE | payload of that round`.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

use crate::codec::{self, Frame};
use crate::round::StoredRound;
use crate::segment::Tail;

const MAGIC: &[u8; 8] = b"RLWAL\0\0\x01";
const HEADER_LEN: usize = 8 + 8 + 4;

/// `(series, round)` pairs in log order.
pub(crate) type Records = Vec<(u64, StoredRound)>;

#[derive(Debug)]
pub(crate) struct WalWriter {
    file: BufWriter<File>,
    seq: u64,
    bytes: u64,
    dirty: bool,
}

impl WalWriter {
    /// Create a new, empty WAL file. Fails if it already exists.
    pub(crate) fn create(path: PathBuf, seq: u64) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut file = BufWriter::with_capacity(256 << 10, file);
        let mut h = Vec::with_capacity(HEADER_LEN);
        h.extend_from_slice(MAGIC);
        h.extend_from_slice(&seq.to_le_bytes());
        let crc = crc32c::crc32c(&h);
        h.extend_from_slice(&crc.to_le_bytes());
        file.write_all(&h)?;
        file.flush()?;
        file.get_ref().sync_all()?;
        Ok(Self {
            file,
            seq,
            bytes: HEADER_LEN as u64,
            dirty: false,
        })
    }

    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Buffer one round. It is durable only after the next [`sync`](Self::sync).
    pub(crate) fn append(&mut self, series: u64, round: &StoredRound) -> io::Result<()> {
        let mut body = Vec::with_capacity(64);
        body.extend_from_slice(&series.to_le_bytes());
        codec::encode_payload(std::slice::from_ref(round), &mut body);
        let mut frame = Vec::with_capacity(codec::FRAME_HEADER + body.len());
        codec::put_frame(&mut frame, &body);
        self.file.write_all(&frame)?;
        self.bytes += frame.len() as u64;
        self.dirty = true;
        Ok(())
    }

    /// Write out buffered rounds and `fsync` them.
    pub(crate) fn sync(&mut self) -> io::Result<()> {
        if self.dirty {
            self.file.flush()?;
            self.file.get_ref().sync_data()?;
            self.dirty = false;
        }
        Ok(())
    }
}

/// Every record of a WAL file held in memory, in order, and how it ends.
/// Reading stops at the first torn or corrupt record.
pub(crate) fn read(bytes: &[u8]) -> Result<(Records, Tail), &'static str> {
    let h = bytes.get(..HEADER_LEN).ok_or("WAL header is truncated")?;
    if &h[..8] != MAGIC {
        return Err("not a WAL file (bad magic)");
    }
    let crc = u32::from_le_bytes(h[16..20].try_into().map_err(|_| "header")?);
    if crc32c::crc32c(&h[..16]) != crc {
        return Err("WAL header checksum mismatch");
    }
    let mut pos = HEADER_LEN;
    let mut out = Vec::new();
    let tail = loop {
        if pos == bytes.len() {
            break Tail::Clean;
        }
        match codec::read_frame(&bytes[pos..]) {
            Frame::Ok(body, len) => {
                let Some(series) = body.get(..8).and_then(|b| b.try_into().ok()) else {
                    break Tail::Corrupt;
                };
                let Some(mut rounds) = codec::decode_payload(&body[8..], 1) else {
                    break Tail::Corrupt;
                };
                out.push((u64::from_le_bytes(series), rounds.remove(0)));
                pos += len;
            }
            Frame::Truncated => break Tail::Torn,
            Frame::Corrupt => break Tail::Corrupt,
        }
    };
    Ok((out, tail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::round::ErrorCounts;

    fn round(ts_ms: i64) -> StoredRound {
        StoredRound {
            ts_ms,
            sent: 3,
            rtts_us: vec![1, 2],
            errors: ErrorCounts::default(),
            resolved: Some("::1".parse().unwrap()),
            timing: None,
            flags: 1,
        }
    }

    #[test]
    fn append_sync_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("1.wal");
        let mut w = WalWriter::create(path.clone(), 1).unwrap();
        w.append(5, &round(100)).unwrap();
        w.append(6, &round(200)).unwrap();
        w.sync().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len() as u64, w.bytes());
        let (recs, tail) = read(&bytes).unwrap();
        assert_eq!(tail, Tail::Clean);
        assert_eq!(recs, vec![(5, round(100)), (6, round(200))]);

        let (recs, tail) = read(&bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(tail, Tail::Torn);
        assert_eq!(recs.len(), 1);
    }

    #[test]
    fn existing_file_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("1.wal");
        WalWriter::create(path.clone(), 1).unwrap();
        assert!(WalWriter::create(path, 1).is_err());
    }
}
