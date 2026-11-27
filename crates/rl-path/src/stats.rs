//! Per-TTL statistics over many sweeps, as `routelith trace` prints them.

use serde::Serialize;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::{Outcome, Sweep};

/// RTTs kept per hop for the median; older ones are dropped.
const KEEP_RTTS: usize = 10_000;

/// A host that answered at one TTL, and how often.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Responder {
    pub addr: IpAddr,
    pub replies: u64,
}

/// Statistics of one TTL.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct HopStats {
    pub ttl: u8,
    pub sent: u64,
    pub received: u64,
    /// Answers that were Unreachable.
    pub unreachable: u64,
    pub send_failed: u64,
    /// Most answers first (ECMP shows as several).
    pub responders: Vec<Responder>,
    /// Whether this is the TTL where the path ended (echo reply or
    /// Unreachable) in the newest sweep that ended it.
    pub is_dest: bool,
    pub last_us: Option<u64>,
    pub min_us: Option<u64>,
    pub max_us: Option<u64>,
    pub mean_us: Option<f64>,
    pub median_us: Option<u64>,
    pub stddev_us: Option<f64>,
    /// Mean absolute difference of consecutive RTTs (as mtr's jitter).
    pub jitter_us: Option<f64>,
}

impl HopStats {
    /// Echo replies from the destination at this TTL (answers that were
    /// not Unreachable).
    pub fn replies(&self) -> u64 {
        if self.is_dest {
            self.received - self.unreachable
        } else {
            0
        }
    }

    /// Lost share in percent; 0 when nothing was sent.
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            100.0 * (self.sent - self.received) as f64 / self.sent as f64
        }
    }
}

#[derive(Debug, Default, Clone)]
struct Acc {
    sent: u64,
    received: u64,
    unreachable: u64,
    send_failed: u64,
    responders: HashMap<IpAddr, u64>,
    rtts: Vec<u64>,
    last: Option<u64>,
    sum: f64,
    sum_sq: f64,
    min: Option<u64>,
    max: Option<u64>,
    jitter_sum: f64,
    jitter_n: u64,
}

/// Running statistics of a trace.
#[derive(Debug, Default, Clone)]
pub struct TraceStats {
    hops: Vec<Acc>,
    sweeps: u64,
    /// Destination distance in the newest sweep that reached it.
    dest_ttl: Option<u8>,
}

impl TraceStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sweeps(&self) -> u64 {
        self.sweeps
    }

    pub fn add(&mut self, sweep: &Sweep) {
        self.sweeps += 1;
        if self.hops.len() < sweep.hops.len() {
            self.hops.resize_with(sweep.hops.len(), Acc::default);
        }
        let dest = sweep.dest_ttl();
        if dest.is_some() {
            self.dest_ttl = dest;
        }
        for (i, outcome) in sweep.hops.iter().enumerate() {
            let acc = &mut self.hops[i];
            acc.sent += 1;
            match outcome {
                Outcome::Lost => {}
                Outcome::SendFailed(_) => acc.send_failed += 1,
                answered => {
                    if matches!(answered, Outcome::Unreachable { .. }) {
                        acc.unreachable += 1;
                    }
                    if let Some(from) = answered.responder() {
                        *acc.responders.entry(from).or_default() += 1;
                    }
                    if let Some(rtt) = answered.rtt() {
                        acc.received += 1;
                        let us = u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX);
                        if let Some(last) = acc.last {
                            acc.jitter_sum += last.abs_diff(us) as f64;
                            acc.jitter_n += 1;
                        }
                        acc.last = Some(us);
                        acc.sum += us as f64;
                        acc.sum_sq += (us as f64) * (us as f64);
                        acc.min = Some(acc.min.map_or(us, |m| m.min(us)));
                        acc.max = Some(acc.max.map_or(us, |m| m.max(us)));
                        if acc.rtts.len() == KEEP_RTTS {
                            acc.rtts.remove(0);
                        }
                        acc.rtts.push(us);
                    }
                }
            }
        }
    }

    /// Rows to show: up to the destination if it was reached, else up to
    /// the highest TTL that ever answered (at least one row).
    pub fn hops(&self) -> Vec<HopStats> {
        let last = match self.dest_ttl {
            Some(d) => usize::from(d),
            None => self
                .hops
                .iter()
                .rposition(|a| !a.responders.is_empty())
                .map_or(1, |i| i + 1),
        }
        .min(self.hops.len());
        self.hops[..last]
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let mut responders: Vec<Responder> = a
                    .responders
                    .iter()
                    .map(|(&addr, &replies)| Responder { addr, replies })
                    .collect();
                responders.sort_by(|x, y| y.replies.cmp(&x.replies).then(x.addr.cmp(&y.addr)));
                let n = a.received as f64;
                let mean = (a.received > 0).then(|| a.sum / n);
                let stddev = mean.map(|m| (a.sum_sq / n - m * m).max(0.0).sqrt());
                let mut sorted = a.rtts.clone();
                sorted.sort_unstable();
                let mid = sorted.len() / 2;
                let median = match sorted.len() {
                    0 => None,
                    n if n % 2 == 1 => Some(sorted[mid]),
                    // Mean of the two middle values, without overflow.
                    _ => Some(
                        sorted[mid - 1] / 2
                            + sorted[mid] / 2
                            + (sorted[mid - 1] % 2 + sorted[mid] % 2) / 2,
                    ),
                };
                HopStats {
                    ttl: u8::try_from(i + 1).unwrap_or(u8::MAX),
                    sent: a.sent,
                    received: a.received,
                    unreachable: a.unreachable,
                    send_failed: a.send_failed,
                    responders,
                    is_dest: Some(i + 1) == self.dest_ttl.map(usize::from),
                    last_us: a.last,
                    min_us: a.min,
                    max_us: a.max,
                    mean_us: mean,
                    median_us: median,
                    stddev_us: stddev,
                    jitter_us: (a.jitter_n > 0).then(|| a.jitter_sum / a.jitter_n as f64),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    use rl_core::TimingBackend;

    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn te(n: u8, ms: u64) -> Outcome {
        Outcome::TimeExceeded {
            from: ip(n),
            rtt: Duration::from_millis(ms),
        }
    }

    fn reply(ms: u64) -> Outcome {
        Outcome::Reply {
            from: ip(100),
            rtt: Duration::from_millis(ms),
        }
    }

    fn sweep(hops: Vec<Outcome>) -> Sweep {
        Sweep {
            start: SystemTime::UNIX_EPOCH,
            hops,
            timing: TimingBackend::LinuxKernelTimestamp,
        }
    }

    #[test]
    fn loss_rtt_and_ecmp_per_hop() {
        let mut st = TraceStats::new();
        st.add(&sweep(vec![te(1, 1), te(2, 2), reply(3), reply(3)]));
        st.add(&sweep(vec![te(1, 3), Outcome::Lost, reply(5)]));
        st.add(&sweep(vec![te(1, 2), te(7, 4), reply(4)]));
        st.add(&sweep(vec![te(1, 2), te(2, 2), reply(4)]));
        let hops = st.hops();
        assert_eq!(hops.len(), 3, "stops at the destination");
        assert_eq!(hops[0].loss_pct(), 0.0);
        assert_eq!(hops[0].min_us, Some(1000));
        assert_eq!(hops[0].max_us, Some(3000));
        assert_eq!(
            hops[0].median_us,
            Some(2000),
            "mean of 2 and 2 (1, 2, 2, 3)"
        );
        assert_eq!(hops[0].mean_us, Some(2000.0));
        assert_eq!(hops[0].jitter_us, Some(1000.0));
        assert_eq!(hops[1].loss_pct(), 25.0);
        assert_eq!(
            hops[1].responders,
            vec![
                Responder {
                    addr: ip(2),
                    replies: 2
                },
                Responder {
                    addr: ip(7),
                    replies: 1
                }
            ]
        );
        assert!(hops[2].is_dest && !hops[1].is_dest);
        assert_eq!(hops[2].sent, 4);
        assert_eq!(hops[2].last_us, Some(4000));
    }

    #[test]
    fn even_median_is_the_mean_of_the_middle_two() {
        let mut st = TraceStats::new();
        st.add(&sweep(vec![reply(10)]));
        st.add(&sweep(vec![reply(31)]));
        assert_eq!(st.hops()[0].median_us, Some(20_500));
    }

    #[test]
    fn unreachable_ends_the_path_but_is_no_reply() {
        let mut st = TraceStats::new();
        let unreach = Outcome::Unreachable {
            from: Some(ip(1)),
            code: 1,
            rtt: Duration::from_millis(1),
        };
        st.add(&sweep(vec![unreach]));
        let hops = st.hops();
        assert!(hops[0].is_dest);
        assert_eq!(hops[0].replies(), 0);
    }

    #[test]
    fn a_lost_final_reply_keeps_the_destination() {
        let mut st = TraceStats::new();
        st.add(&sweep(vec![te(1, 1), reply(2)]));
        st.add(&sweep(vec![te(1, 1), Outcome::Lost]));
        assert!(st.hops()[1].is_dest);
    }

    #[test]
    fn unreached_destination_shows_up_to_the_last_answer() {
        let mut st = TraceStats::new();
        st.add(&sweep(vec![
            te(1, 1),
            Outcome::Lost,
            te(3, 3),
            Outcome::Lost,
            Outcome::Lost,
        ]));
        let hops = st.hops();
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[1].loss_pct(), 100.0);
        assert!(!hops[2].is_dest);
    }
}
