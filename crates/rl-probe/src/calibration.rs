//! Calibration of the Windows ICMP helper API against a raw-socket reference
//! (architecture doc, risk R1).
//!
//! Each pair sends one echo through `IcmpSendEcho2Ex` and one through a raw
//! ICMP socket, alternating which goes first, and times both with `Instant`.
//! The raw socket path is much thinner, so the per-pair difference
//! `api - raw` is the error the helper API adds to an RTT.
//!
//! The analysis is portable so it can be unit tested anywhere; only
//! `run` needs Windows.

use std::time::Duration;

/// One calibration pair. `None` means that side got no reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pair {
    /// QPC-timed duration of the helper API call.
    pub api: Option<Duration>,
    /// The API's own `RoundTripTime` field (milliseconds).
    pub api_rtt_ms: Option<u32>,
    /// QPC-timed send-to-receive time on the raw socket.
    pub raw: Option<Duration>,
}

/// Distribution summary in nanoseconds (nearest-rank percentiles). Kept at
/// the timer's native precision; round only for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dist {
    pub count: usize,
    pub min: i64,
    pub median: i64,
    pub p90: i64,
    pub p99: i64,
    pub max: i64,
}

impl Dist {
    /// `None` for an empty input.
    pub fn from_ns(mut values: Vec<i64>) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        values.sort_unstable();
        let rank = |p: f64| {
            // Nearest rank: ceil(p * n), 1-based.
            let n = values.len();
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss
            )]
            let r = ((p * n as f64).ceil() as usize).clamp(1, n);
            values[r - 1]
        };
        Some(Self {
            count: values.len(),
            min: values[0],
            median: rank(0.5),
            p90: rank(0.9),
            p99: rank(0.99),
            max: values[values.len() - 1],
        })
    }
}

/// Result of a calibration run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub pairs: usize,
    pub api: Option<Dist>,
    pub raw: Option<Dist>,
    /// `api - raw` for pairs where both sides got a reply.
    pub diff: Option<Dist>,
    /// `|api - raw|`: the error the API adds, uncorrected.
    pub abs_err: Option<Dist>,
    /// `|api - raw - median(api - raw)|`: the error left after subtracting a
    /// constant offset, i.e. what a fixed correction could not remove.
    pub abs_err_corrected: Option<Dist>,
    /// Pairs where the API's millisecond `RoundTripTime` differs from the
    /// raw reference by more than 1 ms.
    pub api_field_off: usize,
}

impl Summary {
    pub fn from_pairs(pairs: &[Pair]) -> Self {
        let ns = |d: Duration| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX);
        let api: Vec<i64> = pairs.iter().filter_map(|p| p.api).map(ns).collect();
        let raw: Vec<i64> = pairs.iter().filter_map(|p| p.raw).map(ns).collect();
        let both: Vec<(i64, i64, Option<u32>)> = pairs
            .iter()
            .filter_map(|p| Some((ns(p.api?), ns(p.raw?), p.api_rtt_ms)))
            .collect();
        let diff: Vec<i64> = both.iter().map(|(a, r, _)| a - r).collect();
        let diff_dist = Dist::from_ns(diff.clone());
        let offset = diff_dist.map_or(0, |d| d.median);
        let api_field_off = both
            .iter()
            .filter(|(_, r, ms)| {
                ms.is_some_and(|ms| (i64::from(ms) * 1_000_000 - r).abs() > 1_000_000)
            })
            .count();
        Self {
            pairs: pairs.len(),
            api: Dist::from_ns(api),
            raw: Dist::from_ns(raw),
            abs_err: Dist::from_ns(diff.iter().map(|d| d.abs()).collect()),
            abs_err_corrected: Dist::from_ns(diff.iter().map(|d| (d - offset).abs()).collect()),
            diff: diff_dist,
            api_field_off,
        }
    }
}

/// Nonce seed for one run: the low 32 bits of the clock (nanoseconds) and
/// the low 16 bits of a process-wide run counter fill bits 16..64, and the
/// low 16 bits are left for the sequence number. Runs in one process with
/// different counters (mod 65536) always get different seeds; a collision
/// needs 65,536 runs in flight at once.
#[cfg_attr(not(windows), allow(dead_code))]
fn nonce_seed(run_id: u64, clock_ns: u64) -> u64 {
    ((run_id & 0xffff) << 48) | ((clock_ns & 0xffff_ffff) << 16)
}

/// Run `count` calibration pairs against an IPv4 target, `interval` apart.
/// Blocking; needs Administrator for the raw socket.
#[cfg(windows)]
pub fn run(
    dest: std::net::Ipv4Addr,
    count: u16,
    interval: Duration,
    timeout: Duration,
    payload_size: usize,
) -> std::io::Result<Vec<Pair>> {
    use std::net::IpAddr;
    use std::time::Instant;

    use std::sync::atomic::{AtomicU64, Ordering};

    use rl_sys::windows::{EchoOutcome, IcmpHandle, RawIcmpSocket};

    use crate::packet::{MIN_PAYLOAD, build_echo_request, parse_echo_reply};

    if timeout.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "timeout must be greater than zero",
        ));
    }
    let api = IcmpHandle::open(false)?;
    let mut raw = RawIcmpSocket::open()?;
    let payload: Vec<u8> = (0..payload_size.max(MIN_PAYLOAD))
        .map(|i| (i % 256) as u8)
        .collect();
    let ident = (std::process::id() & 0xffff) as u16;
    // Per-run seed, so overlapping runs in one process don't accept each
    // other's replies: a process-wide run counter in the top bits, and the
    // clock so separate processes differ too. The low 16 bits carry seq.
    // Seeds can repeat only when more than 65,535 runs started after this one
    // and one of them is still running, which a calibration never does.
    static RUN: AtomicU64 = AtomicU64::new(0);
    let run_id = RUN.fetch_add(1, Ordering::Relaxed);
    let clock = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let seed = nonce_seed(run_id, clock);
    let mut buf = vec![0u8; 65536];

    let mut raw_echo = |seq: u16, buf: &mut [u8]| -> std::io::Result<Option<Duration>> {
        let nonce = seed ^ u64::from(seq);
        let packet = build_echo_request(false, ident, seq, nonce, payload.len());
        let start = Instant::now();
        raw.send_to(&packet, dest)?;
        loop {
            let left = timeout.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Ok(None);
            }
            let n = match raw.recv(buf, left) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            let elapsed = start.elapsed();
            if elapsed > timeout {
                return Ok(None);
            }
            // Skip the IPv4 header (IHL is in 32-bit words).
            let ihl = usize::from(buf[0] & 0x0f) * 4;
            let Some(icmp) = buf.get(ihl..n) else {
                continue;
            };
            // Only replies from the target (IPv4 source address, bytes 12..16).
            if buf[..n].get(12..16) != Some(&dest.octets()[..]) {
                continue;
            }
            if let Some(reply) = parse_echo_reply(false, icmp) {
                if reply.ident == ident && reply.seq == seq && reply.nonce == Some(nonce) {
                    return Ok(Some(elapsed));
                }
            }
        }
    };
    let api_echo = || -> std::io::Result<(Option<Duration>, Option<u32>)> {
        Ok(match api.echo(IpAddr::V4(dest), &payload, 128, timeout)? {
            // Same cutoff as the raw side: a reply after the deadline is a loss.
            EchoOutcome::Reply {
                elapsed,
                api_rtt_ms,
                ..
            } if elapsed <= timeout => (Some(elapsed), Some(api_rtt_ms)),
            _ => (None, None),
        })
    };

    let mut pairs = Vec::with_capacity(usize::from(count));
    let mut next = Instant::now();
    for seq in 0..count {
        // Alternate the order so neither side always runs on a warm path.
        let (api_res, raw_res) = if seq % 2 == 0 {
            let a = api_echo()?;
            (a, raw_echo(seq, &mut buf)?)
        } else {
            let r = raw_echo(seq, &mut buf)?;
            (api_echo()?, r)
        };
        pairs.push(Pair {
            api: api_res.0,
            api_rtt_ms: api_res.1,
            raw: raw_res,
        });
        if seq + 1 == count {
            break;
        }
        next += interval;
        if let Some(wait) = next.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
    }
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(api_us: u64, raw_us: u64) -> Pair {
        Pair {
            api: Some(Duration::from_micros(api_us)),
            api_rtt_ms: Some(u32::try_from(api_us / 1000).unwrap()),
            raw: Some(Duration::from_micros(raw_us)),
        }
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let d = Dist::from_ns((1..=100).collect()).unwrap();
        assert_eq!((d.min, d.median, d.p90, d.p99, d.max), (1, 50, 90, 99, 100));
        assert_eq!(Dist::from_ns(vec![]), None);
    }

    #[test]
    fn constant_offset_is_removed_by_correction() {
        // API always 300 µs slower than raw, except one 900 µs outlier.
        let mut pairs: Vec<Pair> = (0..99).map(|i| pair(1300 + i, 1000 + i)).collect();
        pairs.push(pair(1900, 1000));
        let s = Summary::from_pairs(&pairs);
        assert_eq!(s.diff.unwrap().median, 300_000);
        assert_eq!(s.abs_err.unwrap().p99, 300_000);
        assert_eq!(s.abs_err.unwrap().max, 900_000);
        assert_eq!(s.abs_err_corrected.unwrap().median, 0);
        assert_eq!(s.abs_err_corrected.unwrap().max, 600_000);
    }

    #[test]
    fn unmatched_sides_are_left_out_of_the_difference() {
        let pairs = [
            pair(500, 400),
            Pair {
                api: None,
                api_rtt_ms: None,
                raw: Some(Duration::from_micros(400)),
            },
            Pair {
                api: Some(Duration::from_micros(500)),
                api_rtt_ms: Some(0),
                raw: None,
            },
        ];
        let s = Summary::from_pairs(&pairs);
        assert_eq!(s.pairs, 3);
        assert_eq!(s.api.unwrap().count, 2);
        assert_eq!(s.raw.unwrap().count, 2);
        assert_eq!(s.diff.unwrap().count, 1);
    }

    #[test]
    fn api_millisecond_field_is_checked_against_raw() {
        let mut p = pair(5000, 5000);
        p.api_rtt_ms = Some(7); // 2 ms off
        let s = Summary::from_pairs(&[p, pair(5000, 5000)]);
        assert_eq!(s.api_field_off, 1);
    }

    #[test]
    fn seeds_differ_per_run_with_the_same_clock() {
        let a = nonce_seed(0, 123_456_789);
        let b = nonce_seed(1, 123_456_789);
        assert_ne!(a, b);
        // The sequence number's bits stay free.
        assert_eq!(a & 0xffff, 0);
        assert_eq!(b & 0xffff, 0);
        assert_ne!(nonce_seed(0, 1), nonce_seed(0, 2));
    }

    #[test]
    fn sub_microsecond_differences_are_kept() {
        let p = Pair {
            api: Some(Duration::from_nanos(1_000_900)),
            api_rtt_ms: Some(1),
            raw: Some(Duration::from_nanos(1_000_100)),
        };
        let s = Summary::from_pairs(&[p]);
        assert_eq!(s.diff.unwrap().median, 800);
    }
}
