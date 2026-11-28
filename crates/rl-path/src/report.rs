//! A traced target's hop table over a window, read from the store
//! (architecture doc §21.9 P14): what `GET /api/v1/paths/{target}` and
//! `routelith ctl report path` show.
//!
//! The raw sweeps give everything: who answered at each TTL (ECMP shows as
//! several), loss and the RTT statistics. Past [`MAX_SWEEP_SPAN_MS`], or
//! once the raw tier has dropped the window, the hop series stand in: the
//! same loss and RTTs per step, but no responders, last or jitter.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rl_core::TimingBackend;
use rl_core::addr::{AddrClass, classify};
use rl_store::{Reader, StoreError, TraceHop, TraceRecord};
use serde::Serialize;

use crate::enrich::HopInfo;
use crate::{Outcome, Sweep, TraceStats};

/// Longest window read from the raw sweeps (a day of 2.5 s sweeps is
/// 34 560); longer windows use the hop series.
pub const MAX_SWEEP_SPAN_MS: i64 = 24 * 3_600_000;

/// Where a report's numbers come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The raw sweeps: responders, last and jitter included.
    Sweeps,
    /// The hop series (one round per TTL per step): no responders.
    HopSeries,
}

/// A host that answered at one TTL.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResponderRow {
    pub addr: IpAddr,
    pub replies: u64,
    /// Share of this TTL's answers, percent (ECMP).
    pub share_pct: f64,
    pub class: AddrClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<Arc<str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<Arc<str>>,
}

/// One TTL of the hop table. Times are microseconds.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HopRow {
    pub ttl: u8,
    /// The hop series, for its timeline (`/api/v1/series/{id}/data`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub series: Option<u64>,
    pub sent: u64,
    pub received: u64,
    pub loss_pct: f64,
    /// Whether the path ends here (the destination, or an Unreachable).
    pub is_dest: bool,
    pub min_us: Option<u64>,
    pub median_us: Option<u64>,
    pub avg_us: Option<f64>,
    pub max_us: Option<u64>,
    pub last_us: Option<u64>,
    /// Mean difference of consecutive RTTs, as mtr shows it.
    pub jitter_us: Option<f64>,
    /// Most answers first; empty from the hop series.
    pub responders: Vec<ResponderRow>,
}

/// A hop table and what it was made from.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PathReport {
    pub from_ms: i64,
    pub to_ms: i64,
    pub source: Source,
    /// Raw sweeps read (0 from the hop series).
    pub sweeps: u64,
    /// Hop rounds of the first hop in the window.
    pub rounds: usize,
    pub hops: Vec<HopRow>,
}

impl PathReport {
    /// Every responder address, once, in table order.
    pub fn addrs(&self) -> Vec<IpAddr> {
        let mut seen = HashSet::new();
        self.hops
            .iter()
            .flat_map(|h| h.responders.iter().map(|r| r.addr))
            .filter(|a| seen.insert(*a))
            .collect()
    }

    /// Fills in names, AS numbers and owners from `info`.
    pub fn enrich(&mut self, info: &HashMap<IpAddr, HopInfo>) {
        for r in self.hops.iter_mut().flat_map(|h| h.responders.iter_mut()) {
            if let Some(i) = info.get(&r.addr) {
                r.rdns.clone_from(&i.rdns);
                r.asn = i.asn;
                r.org.clone_from(&i.org);
                r.country.clone_from(&i.country);
                r.class = i.class;
            }
        }
    }
}

/// A stored sweep as the tracer reported it.
pub fn sweep_of(r: &TraceRecord) -> Sweep {
    let rtt = |us: u32| Duration::from_micros(u64::from(us));
    let start =
        u64::try_from(r.ts_ms).map_or(UNIX_EPOCH, |ms| UNIX_EPOCH + Duration::from_millis(ms));
    Sweep {
        start,
        hops: r
            .hops
            .iter()
            .map(|h| match *h {
                TraceHop::Lost => Outcome::Lost,
                TraceHop::SendFailed => Outcome::SendFailed(String::new()),
                TraceHop::TimeExceeded { from, rtt_us } => Outcome::TimeExceeded {
                    from,
                    rtt: rtt(rtt_us),
                },
                TraceHop::Reply { from, rtt_us } => Outcome::Reply {
                    from,
                    rtt: rtt(rtt_us),
                },
                TraceHop::Unreachable { from, code, rtt_us } => Outcome::Unreachable {
                    from,
                    code,
                    rtt: rtt(rtt_us),
                },
            })
            .collect(),
        timing: r.timing.unwrap_or(TimingBackend::Monotonic),
    }
}

/// A sweep as the raw trace tier keeps it.
pub fn record_of(s: &Sweep) -> TraceRecord {
    let us = |d: Duration| u32::try_from(d.as_micros()).unwrap_or(u32::MAX);
    let ts_ms = s
        .start
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    TraceRecord {
        ts_ms,
        timing: Some(s.timing),
        hops: s
            .hops
            .iter()
            .map(|h| match *h {
                Outcome::TimeExceeded { from, rtt } => TraceHop::TimeExceeded {
                    from,
                    rtt_us: us(rtt),
                },
                Outcome::Reply { from, rtt } => TraceHop::Reply {
                    from,
                    rtt_us: us(rtt),
                },
                Outcome::Unreachable { from, code, rtt } => TraceHop::Unreachable {
                    from,
                    code,
                    rtt_us: us(rtt),
                },
                Outcome::Lost => TraceHop::Lost,
                Outcome::SendFailed(_) => TraceHop::SendFailed,
            })
            .collect(),
    }
}

fn loss_pct(sent: u64, received: u64) -> f64 {
    if sent == 0 {
        0.0
    } else {
        100.0 * sent.saturating_sub(received) as f64 / sent as f64
    }
}

/// The hop table of some sweeps (oldest first). `hop_ids[ttl - 1]` is
/// that TTL's hop series.
pub fn from_sweeps(records: &[TraceRecord], hop_ids: &[u64]) -> Vec<HopRow> {
    let mut stats = TraceStats::new();
    for r in records {
        stats.add(&sweep_of(r));
    }
    stats
        .hops()
        .into_iter()
        .map(|h| {
            let total: u64 = h.responders.iter().map(|r| r.replies).sum();
            HopRow {
                ttl: h.ttl,
                series: hop_ids.get(usize::from(h.ttl) - 1).copied(),
                sent: h.sent,
                received: h.received,
                loss_pct: loss_pct(h.sent, h.received),
                is_dest: h.is_dest,
                min_us: h.min_us,
                median_us: h.median_us,
                avg_us: h.mean_us,
                max_us: h.max_us,
                last_us: h.last_us,
                jitter_us: h.jitter_us,
                responders: h
                    .responders
                    .into_iter()
                    .map(|r| ResponderRow {
                        addr: r.addr,
                        replies: r.replies,
                        share_pct: 100.0 * r.replies as f64 / total.max(1) as f64,
                        class: classify(r.addr),
                        rdns: None,
                        asn: None,
                        org: None,
                        country: None,
                    })
                    .collect(),
            }
        })
        .collect()
}

/// The hop table of hop-series rounds: `hops[ttl - 1]` is that TTL's
/// series and rounds. Rows end at the highest TTL that has rounds.
pub fn from_hop_rounds(hops: &[(u64, Vec<rl_store::StoredRound>)]) -> Vec<HopRow> {
    let mut rows: Vec<HopRow> = hops
        .iter()
        .enumerate()
        .map(|(i, (id, rounds))| {
            let mut rtts: Vec<u64> = rounds
                .iter()
                .flat_map(|r| r.rtts_us.iter().map(|&us| u64::from(us)))
                .collect();
            rtts.sort_unstable();
            let sent: u64 = rounds.iter().map(|r| u64::from(r.sent)).sum();
            let received = rtts.len() as u64;
            let mid = rtts.len() / 2;
            let median = match rtts.len() {
                0 => None,
                n if n % 2 == 1 => Some(rtts[mid]),
                _ => Some(
                    rtts[mid - 1] / 2 + rtts[mid] / 2 + (rtts[mid - 1] % 2 + rtts[mid] % 2) / 2,
                ),
            };
            HopRow {
                ttl: u8::try_from(i + 1).unwrap_or(u8::MAX),
                series: Some(*id),
                sent,
                received,
                loss_pct: loss_pct(sent, received),
                is_dest: false,
                min_us: rtts.first().copied(),
                median_us: median,
                avg_us: (received > 0).then(|| rtts.iter().sum::<u64>() as f64 / received as f64),
                max_us: rtts.last().copied(),
                last_us: None,
                jitter_us: None,
                responders: Vec::new(),
            }
        })
        .collect();
    // Hop series stop at the destination, so TTLs past it have no rounds.
    let last = rows.iter().rposition(|r| r.sent > 0).map_or(0, |i| i + 1);
    rows.truncate(last);
    rows
}

/// The hop table of one trace over `from_ms..to_ms`: from the raw sweeps
/// `raw_id` if the window is short enough and they hold any, else from the
/// hop series `hop_ids` (TTL 1 first).
pub fn read(
    reader: &Reader,
    dir: &Path,
    raw_id: u64,
    hop_ids: &[u64],
    from_ms: i64,
    to_ms: i64,
) -> Result<PathReport, StoreError> {
    let first_rounds = |reader: &Reader| -> Result<usize, StoreError> {
        match hop_ids.first() {
            Some(&id) => Ok(reader.read(id, from_ms, to_ms)?.len()),
            None => Ok(0),
        }
    };
    if to_ms.saturating_sub(from_ms) <= MAX_SWEEP_SPAN_MS {
        let records = rl_store::read_trace(dir, raw_id, from_ms, to_ms)?;
        if !records.is_empty() {
            return Ok(PathReport {
                from_ms,
                to_ms,
                source: Source::Sweeps,
                sweeps: records.len() as u64,
                rounds: first_rounds(reader)?,
                hops: from_sweeps(&records, hop_ids),
            });
        }
    }
    let mut per_ttl = Vec::with_capacity(hop_ids.len());
    for &id in hop_ids {
        per_ttl.push((id, reader.read(id, from_ms, to_ms)?));
    }
    Ok(PathReport {
        from_ms,
        to_ms,
        source: Source::HopSeries,
        sweeps: 0,
        rounds: per_ttl.first().map_or(0, |(_, r)| r.len()),
        hops: from_hop_rounds(&per_ttl),
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn rec(ts_ms: i64, hops: Vec<TraceHop>) -> TraceRecord {
        TraceRecord {
            ts_ms,
            timing: Some(TimingBackend::LinuxKernelTimestamp),
            hops,
        }
    }

    #[test]
    fn records_and_sweeps_convert_both_ways() {
        let r = rec(
            1_700_000_000_000,
            vec![
                TraceHop::TimeExceeded {
                    from: ip(10, 0, 0, 1),
                    rtt_us: 500,
                },
                TraceHop::Lost,
                TraceHop::SendFailed,
                TraceHop::Unreachable {
                    from: None,
                    code: 3,
                    rtt_us: 900,
                },
            ],
        );
        assert_eq!(record_of(&sweep_of(&r)), r);
    }

    #[test]
    fn sweeps_give_ecmp_shares_and_classes() {
        let te = |from, rtt_us| TraceHop::TimeExceeded { from, rtt_us };
        let dest = ip(1, 1, 1, 1);
        let records: Vec<TraceRecord> = (0..4)
            .map(|i| {
                // Hop 2 alternates between two routers (ECMP); one sweep in
                // four loses it.
                let hop2 = match i {
                    0 | 2 => te(ip(203, 0, 113, 1), 2000),
                    1 => te(ip(203, 0, 113, 2), 2100),
                    _ => TraceHop::Lost,
                };
                rec(
                    i * 2500,
                    vec![
                        te(ip(192, 168, 1, 1), 300 + 10 * u32::try_from(i).unwrap()),
                        hop2,
                        TraceHop::Reply {
                            from: dest,
                            rtt_us: 9000,
                        },
                    ],
                )
            })
            .collect();
        let rows = from_sweeps(&records, &[11, 12, 13]);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].series, Some(11));
        assert_eq!(rows[0].responders[0].class, AddrClass::Private);
        assert_eq!(rows[0].last_us, Some(330));
        assert_eq!(rows[0].jitter_us, Some(10.0));
        let h2 = &rows[1];
        assert_eq!((h2.sent, h2.received), (4, 3));
        assert_eq!(h2.loss_pct, 25.0);
        assert_eq!(h2.responders.len(), 2);
        assert_eq!(h2.responders[0].addr, ip(203, 0, 113, 1));
        assert!((h2.responders[0].share_pct - 200.0 / 3.0).abs() < 1e-9);
        assert_eq!(h2.responders[0].class, AddrClass::Documentation);
        assert!(rows[2].is_dest);
        assert_eq!(rows[2].responders[0].class, AddrClass::Public);
    }

    #[test]
    fn hop_rounds_stand_in_without_responders() {
        let round = |ts_ms, sent, rtts_us: Vec<u32>| rl_store::StoredRound {
            ts_ms,
            sent,
            rtts_us,
            errors: rl_store::ErrorCounts::default(),
            resolved: None,
            timing: None,
            flags: 0,
        };
        let hops = vec![
            (
                21,
                vec![
                    round(0, 24, vec![300; 24]),
                    round(60_000, 24, vec![500; 24]),
                ],
            ),
            (
                22,
                vec![round(0, 24, vec![]), round(60_000, 24, vec![2000; 12])],
            ),
            // The destination was at TTL 2: nothing stored past it.
            (23, vec![]),
        ];
        let rows = from_hop_rounds(&hops);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].median_us, Some(400));
        assert_eq!(rows[0].avg_us, Some(400.0));
        assert_eq!((rows[1].sent, rows[1].received), (48, 12));
        assert_eq!(rows[1].loss_pct, 75.0);
        assert_eq!(rows[1].series, Some(22));
        assert!(rows[1].responders.is_empty());
    }

    #[test]
    fn enrich_fills_in_what_is_known() {
        let mut report = PathReport {
            from_ms: 0,
            to_ms: 1,
            source: Source::Sweeps,
            sweeps: 1,
            rounds: 0,
            hops: from_sweeps(
                &[rec(
                    0,
                    vec![
                        TraceHop::TimeExceeded {
                            from: ip(10, 0, 0, 1),
                            rtt_us: 100,
                        },
                        TraceHop::Reply {
                            from: ip(1, 1, 1, 1),
                            rtt_us: 900,
                        },
                    ],
                )],
                &[],
            ),
        };
        assert_eq!(report.addrs(), vec![ip(10, 0, 0, 1), ip(1, 1, 1, 1)]);
        let info = HashMap::from([(
            ip(1, 1, 1, 1),
            HopInfo {
                rdns: Some("one.one.one.one".into()),
                asn: Some(13335),
                org: Some("CLOUDFLARENET".into()),
                country: Some("US".into()),
                class: AddrClass::Public,
            },
        )]);
        report.enrich(&info);
        let r = &report.hops[1].responders[0];
        assert_eq!(r.rdns.as_deref(), Some("one.one.one.one"));
        assert_eq!(r.asn, Some(13335));
        assert_eq!(report.hops[0].responders[0].asn, None);
        assert_eq!(report.hops[0].series, None);
    }
}
