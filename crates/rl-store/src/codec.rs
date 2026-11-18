//! Round encoding (architecture doc §6.3) and the CRC-checked frames that
//! carry it in segments and the WAL.
//!
//! A *payload* encodes `n` rounds column by column:
//!
//! 1. timestamps: first value, first delta, then delta-of-delta (zigzag
//!    varints; with aligned steps the delta-of-delta is almost always 0);
//! 2. `sent`, run-length encoded as `(run, value)` varint pairs;
//! 3. loss (`sent - replies`), run-length encoded the same way;
//! 4. RTT vectors: each round's `rtt[0]` as a zigzag change from the
//!    previous round's, then every round's rank-to-rank deltas (varints);
//! 5. a sparse side table of `(round, tag, value)` entries for the resolved
//!    address and timing backend (only where they change), error counts and
//!    flags (only where non-zero).
//!
//! A *block* is a payload compressed with zstd behind a small uncompressed
//! header (`count`, first and last timestamp) so readers can skip blocks
//! outside a time range without decompressing them.
//!
//! A *frame* is `len: u32 LE | crc32c(body): u32 LE | body`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rl_core::TimingBackend;

use crate::round::{ErrorCounts, StoredRound};
use crate::varint::{Reader, put_i64, put_u64};

/// Upper bound for one frame body; anything larger is treated as corrupt.
pub(crate) const MAX_FRAME: usize = 64 << 20;
pub(crate) const FRAME_HEADER: usize = 8;
const BLOCK_HEADER: usize = 2 + 8 + 8;

const TAG_V4: u8 = 1;
const TAG_V6: u8 = 2;
const TAG_TIMING: u8 = 3;
const TAG_ERRORS: u8 = 4;
const TAG_FLAGS: u8 = 5;

/// Encode rounds (in timestamp order) into an uncompressed payload.
pub(crate) fn encode_payload(rounds: &[StoredRound], out: &mut Vec<u8>) {
    // 1. Timestamps.
    let mut prev_ts = 0i64;
    let mut prev_delta = 0i64;
    for (i, r) in rounds.iter().enumerate() {
        match i {
            0 => put_i64(out, r.ts_ms),
            1 => {
                prev_delta = r.ts_ms.wrapping_sub(prev_ts);
                put_i64(out, prev_delta);
            }
            _ => {
                let delta = r.ts_ms.wrapping_sub(prev_ts);
                put_i64(out, delta.wrapping_sub(prev_delta));
                prev_delta = delta;
            }
        }
        prev_ts = r.ts_ms;
    }
    // 2-3. sent and loss.
    put_rle(out, rounds.iter().map(|r| r.sent));
    put_rle(out, rounds.iter().map(StoredRound::loss));
    // 4. RTT vectors: each round's minimum as a change from the previous
    // round's minimum (consecutive rounds of a target share a base RTT),
    // then all rank-to-rank deltas.
    let mut prev_min = 0i64;
    for r in rounds {
        if let Some(&min) = r.rtts_us.first() {
            put_i64(out, i64::from(min) - prev_min);
            prev_min = i64::from(min);
        }
    }
    for r in rounds {
        for pair in r.rtts_us.windows(2) {
            put_u64(out, u64::from(pair[1] - pair[0]));
        }
    }
    // 5. Side table.
    let mut side = Vec::new();
    let mut entries = 0u64;
    let mut last_idx = 0usize;
    let mut last_resolved = None;
    let mut last_timing = None;
    let mut entry = |side: &mut Vec<u8>, idx: usize, tag: u8| {
        put_u64(side, (idx - last_idx) as u64);
        side.push(tag);
        last_idx = idx;
        entries += 1;
    };
    for (i, r) in rounds.iter().enumerate() {
        if r.resolved.is_some() && r.resolved != last_resolved {
            match r.resolved {
                Some(IpAddr::V4(a)) => {
                    entry(&mut side, i, TAG_V4);
                    side.extend_from_slice(&a.octets());
                }
                Some(IpAddr::V6(a)) => {
                    entry(&mut side, i, TAG_V6);
                    side.extend_from_slice(&a.octets());
                }
                None => {}
            }
            last_resolved = r.resolved;
        }
        if let Some(t) = r.timing.filter(|_| r.timing != last_timing) {
            entry(&mut side, i, TAG_TIMING);
            side.push(t.code());
            last_timing = r.timing;
        }
        if !r.errors.is_zero() {
            entry(&mut side, i, TAG_ERRORS);
            for v in [
                r.errors.unreachable,
                r.errors.time_exceeded,
                r.errors.send_failed,
                r.errors.other,
            ] {
                put_u64(&mut side, u64::from(v));
            }
        }
        if r.flags != 0 {
            entry(&mut side, i, TAG_FLAGS);
            side.push(r.flags);
        }
    }
    put_u64(out, entries);
    out.extend_from_slice(&side);
}

fn put_rle(out: &mut Vec<u8>, values: impl Iterator<Item = u16>) {
    let mut run: Option<(u16, u64)> = None;
    for v in values {
        run = match run {
            Some((cur, n)) if cur == v => Some((cur, n + 1)),
            Some((cur, n)) => {
                put_u64(out, n);
                put_u64(out, u64::from(cur));
                Some((v, 1))
            }
            None => Some((v, 1)),
        };
    }
    if let Some((cur, n)) = run {
        put_u64(out, n);
        put_u64(out, u64::from(cur));
    }
}

fn get_rle(r: &mut Reader<'_>, n: usize) -> Option<Vec<u16>> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let run = usize::try_from(r.u64()?).ok()?;
        let v = r.u16()?;
        if run == 0 || run > n - out.len() {
            return None;
        }
        out.extend(std::iter::repeat_n(v, run));
    }
    Some(out)
}

/// Decode `n` rounds from a payload. `None` if it is malformed.
pub(crate) fn decode_payload(buf: &[u8], n: usize) -> Option<Vec<StoredRound>> {
    let mut r = Reader::new(buf);
    let mut ts = Vec::with_capacity(n);
    let mut delta = 0i64;
    for i in 0..n {
        let v = r.i64()?;
        match i {
            0 => ts.push(v),
            1 => {
                delta = v;
                ts.push(ts[0].checked_add(delta)?);
            }
            _ => {
                delta = delta.checked_add(v)?;
                ts.push(ts[i - 1].checked_add(delta)?);
            }
        }
    }
    let sent = get_rle(&mut r, n)?;
    let loss = get_rle(&mut r, n)?;
    let mut mins = Vec::with_capacity(n);
    let mut prev_min = 0i64;
    for i in 0..n {
        if sent[i].checked_sub(loss[i])? > 0 {
            prev_min = prev_min.checked_add(r.i64()?)?;
            mins.push(u32::try_from(prev_min).ok()?);
        }
    }
    let mut mins = mins.into_iter();
    let mut rounds = Vec::with_capacity(n);
    for i in 0..n {
        let k = sent[i] - loss[i];
        let mut rtts = Vec::with_capacity(usize::from(k));
        if k > 0 {
            let mut v = mins.next()?;
            rtts.push(v);
            for _ in 1..k {
                v = v.checked_add(r.u32()?)?;
                rtts.push(v);
            }
        }
        rounds.push(StoredRound {
            ts_ms: ts[i],
            sent: sent[i],
            rtts_us: rtts,
            errors: ErrorCounts::default(),
            resolved: None,
            timing: None,
            flags: 0,
        });
    }
    let entries = r.u64()?;
    let mut idx = 0usize;
    // Changes recorded per round, then filled forward.
    let mut resolved_at: Vec<(usize, IpAddr)> = Vec::new();
    let mut timing_at: Vec<(usize, Option<TimingBackend>)> = Vec::new();
    for _ in 0..entries {
        idx = idx.checked_add(usize::try_from(r.u64()?).ok()?)?;
        let round = rounds.get_mut(idx)?;
        match r.byte()? {
            TAG_V4 => {
                let o: [u8; 4] = r.bytes(4)?.try_into().ok()?;
                resolved_at.push((idx, IpAddr::V4(Ipv4Addr::from(o))));
            }
            TAG_V6 => {
                let o: [u8; 16] = r.bytes(16)?.try_into().ok()?;
                resolved_at.push((idx, IpAddr::V6(Ipv6Addr::from(o))));
            }
            TAG_TIMING => {
                // An unknown code (from a newer version) reads as "unknown"
                // and ends the previous backend's run.
                timing_at.push((idx, TimingBackend::from_code(r.byte()?)));
            }
            TAG_ERRORS => {
                round.errors = ErrorCounts {
                    unreachable: r.u16()?,
                    time_exceeded: r.u16()?,
                    send_failed: r.u16()?,
                    other: r.u16()?,
                };
            }
            TAG_FLAGS => round.flags = r.byte()?,
            _ => return None,
        }
    }
    if !r.is_empty() {
        return None;
    }
    fill_forward(&mut rounds, &resolved_at, |r, v| r.resolved = Some(v));
    fill_forward(&mut rounds, &timing_at, |r, v| r.timing = v);
    Some(rounds)
}

fn fill_forward<T: Copy>(
    rounds: &mut [StoredRound],
    changes: &[(usize, T)],
    set: impl Fn(&mut StoredRound, T),
) {
    for (n, &(start, v)) in changes.iter().enumerate() {
        let end = changes.get(n + 1).map_or(rounds.len(), |c| c.0);
        for r in rounds.get_mut(start..end).into_iter().flatten() {
            set(r, v);
        }
    }
}

/// Append a frame holding `body`.
pub(crate) fn put_frame(out: &mut Vec<u8>, body: &[u8]) {
    let len = u32::try_from(body.len()).expect("frame bodies are below 4 GiB");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&crc32c::crc32c(body).to_le_bytes());
    out.extend_from_slice(body);
}

/// Outcome of reading one frame from the front of `buf`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Frame<'a> {
    /// A complete frame with a valid checksum, and its total length.
    Ok(&'a [u8], usize),
    /// `buf` ends inside the frame: a torn write at the end of a file.
    Truncated,
    /// The length or checksum is wrong.
    Corrupt,
}

pub(crate) fn read_frame(buf: &[u8]) -> Frame<'_> {
    let Some(head) = buf.get(..FRAME_HEADER) else {
        return Frame::Truncated;
    };
    let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let crc = u32::from_le_bytes([head[4], head[5], head[6], head[7]]);
    if len > MAX_FRAME {
        return Frame::Corrupt;
    }
    let Some(body) = buf.get(FRAME_HEADER..FRAME_HEADER + len) else {
        return Frame::Truncated;
    };
    if crc32c::crc32c(body) != crc {
        return Frame::Corrupt;
    }
    Frame::Ok(body, FRAME_HEADER + len)
}

/// Time range and size of a block, readable without decompressing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockHeader {
    pub(crate) count: u16,
    pub(crate) first_ts: i64,
    pub(crate) last_ts: i64,
}

/// Encode rounds (1 to 65,535, in timestamp order) as a block body.
pub(crate) fn encode_block(rounds: &[StoredRound], level: i32) -> Vec<u8> {
    let count = u16::try_from(rounds.len()).expect("blocks hold at most 65,535 rounds");
    let mut payload = Vec::new();
    encode_payload(rounds, &mut payload);
    let compressed = zstd::bulk::compress(&payload, level).expect("compressing to memory");
    let mut body = Vec::with_capacity(BLOCK_HEADER + compressed.len());
    body.extend_from_slice(&count.to_le_bytes());
    body.extend_from_slice(&rounds.first().map_or(0, |r| r.ts_ms).to_le_bytes());
    body.extend_from_slice(&rounds.last().map_or(0, |r| r.ts_ms).to_le_bytes());
    body.extend_from_slice(&compressed);
    body
}

pub(crate) fn block_header(body: &[u8]) -> Option<BlockHeader> {
    let h = body.get(..BLOCK_HEADER)?;
    Some(BlockHeader {
        count: u16::from_le_bytes([h[0], h[1]]),
        first_ts: i64::from_le_bytes(h[2..10].try_into().ok()?),
        last_ts: i64::from_le_bytes(h[10..18].try_into().ok()?),
    })
}

pub(crate) fn decode_block(body: &[u8]) -> Option<Vec<StoredRound>> {
    let h = block_header(body)?;
    // Each round needs at least a few payload bytes; bound the output so a
    // corrupt header cannot ask for an absurd allocation.
    let compressed = &body[BLOCK_HEADER..];
    // Size the buffer from the frame's declared size when it has one.
    let capacity = zstd::zstd_safe::get_frame_content_size(compressed)
        .ok()
        .flatten()
        .and_then(|n| usize::try_from(n).ok())
        .filter(|&n| n <= MAX_FRAME)
        .unwrap_or(MAX_FRAME);
    let payload = zstd::bulk::decompress(compressed, capacity).ok()?;
    let rounds = decode_payload(&payload, usize::from(h.count))?;
    let ok = rounds.first().map(|r| r.ts_ms) == Some(h.first_ts)
        && rounds.last().map(|r| r.ts_ms) == Some(h.last_ts);
    ok.then_some(rounds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn round(ts_ms: i64, sent: u16, rtts: &[u32]) -> StoredRound {
        StoredRound {
            ts_ms,
            sent,
            rtts_us: rtts.to_vec(),
            errors: ErrorCounts::default(),
            resolved: None,
            timing: None,
            flags: 0,
        }
    }

    fn arb_round() -> impl Strategy<Value = StoredRound> {
        (
            any::<i32>(),
            0u16..=40,
            proptest::collection::vec(any::<u32>(), 0..=40),
            any::<[u16; 4]>(),
            proptest::option::of(any::<std::net::IpAddr>()),
            proptest::option::of(1u8..=3),
            any::<u8>(),
        )
            .prop_map(|(ts, extra_loss, mut rtts, e, resolved, timing, flags)| {
                rtts.sort_unstable();
                let sent = u16::try_from(rtts.len()).unwrap() + extra_loss;
                StoredRound {
                    ts_ms: i64::from(ts),
                    sent,
                    rtts_us: rtts,
                    errors: ErrorCounts {
                        unreachable: e[0],
                        time_exceeded: e[1],
                        send_failed: e[2],
                        other: e[3],
                    },
                    resolved,
                    timing: timing.and_then(TimingBackend::from_code),
                    flags,
                }
            })
    }

    /// What a reader sees: resolved address and timing filled forward.
    fn filled(rounds: &[StoredRound]) -> Vec<StoredRound> {
        let mut out = rounds.to_vec();
        let (mut res, mut tim) = (None, None);
        for r in &mut out {
            res = r.resolved.or(res);
            tim = r.timing.or(tim);
            r.resolved = res;
            r.timing = tim;
        }
        out
    }

    proptest! {
        #[test]
        fn payload_round_trips(rounds in proptest::collection::vec(arb_round(), 0..40)) {
            let mut buf = Vec::new();
            encode_payload(&rounds, &mut buf);
            prop_assert_eq!(decode_payload(&buf, rounds.len()), Some(filled(&rounds)));
        }

        #[test]
        fn block_round_trips(rounds in proptest::collection::vec(arb_round(), 1..40)) {
            let body = encode_block(&rounds, 3);
            prop_assert_eq!(decode_block(&body), Some(filled(&rounds)));
        }

        #[test]
        fn corrupt_payloads_never_panic(buf: Vec<u8>, n in 0usize..50) {
            let _ = decode_payload(&buf, n);
        }
    }

    #[test]
    fn aligned_timestamps_cost_one_byte_each() {
        let rounds: Vec<_> = (0..256)
            .map(|i| round(1_700_000_000_000 + i * 300_000, 0, &[]))
            .collect();
        let mut buf = Vec::new();
        encode_payload(&rounds, &mut buf);
        // ts: 6 bytes first + 3 bytes delta + 254 zeros; sent/loss RLE: 3+3; side: 1.
        assert!(buf.len() < 6 + 3 + 254 + 6 + 6 + 1 + 4, "{}", buf.len());
    }

    #[test]
    fn frames_detect_truncation_and_corruption() {
        let mut buf = Vec::new();
        put_frame(&mut buf, b"hello");
        assert_eq!(read_frame(&buf), Frame::Ok(b"hello", 13));
        assert_eq!(read_frame(&buf[..10]), Frame::Truncated);
        assert_eq!(read_frame(&buf[..3]), Frame::Truncated);
        buf[10] ^= 1;
        assert_eq!(read_frame(&buf), Frame::Corrupt);
    }

    #[test]
    fn block_header_is_readable_without_decompressing() {
        let body = encode_block(&[round(1000, 1, &[5]), round(4000, 2, &[])], 3);
        assert_eq!(
            block_header(&body),
            Some(BlockHeader {
                count: 2,
                first_ts: 1000,
                last_ts: 4000
            })
        );
    }
}
