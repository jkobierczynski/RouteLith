//! What the server knows about each agent now (§21.7 G10, G12): for the
//! agents page, `/api/v1/agents` and `/metrics`.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};

/// An agent whose clock is off by more than this is flagged (§21.7 G10).
pub const CLOCK_LIMIT_MS: f64 = 100.0;
/// Clock samples kept; the one with the lowest round-trip delay counts.
pub const CLOCK_SAMPLES: usize = 8;

/// One agent as the server sees it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AgentStatus {
    pub name: String,
    pub connected: bool,
    /// Where it connects from (the last connection).
    pub addr: Option<SocketAddr>,
    pub version: String,
    pub os: String,
    pub capabilities: Vec<String>,
    /// Since when it is connected, or was last.
    pub connected_ms: Option<i64>,
    /// Its last message.
    pub last_seen_ms: Option<i64>,
    /// Agent clock minus server clock, and the round trip of that sample.
    pub clock_offset_ms: Option<f64>,
    pub clock_delay_ms: Option<f64>,
    /// Off by more than [`CLOCK_LIMIT_MS`].
    pub clock_skewed: bool,
    /// Timing backends of its rounds (rl_core::TimingBackend codes).
    pub timing: BTreeSet<u8>,
    pub spool_bytes: Option<u64>,
    pub spool_backlog: Option<u64>,
    /// Rounds it measured that never arrived (its spool dropped them),
    /// since the server started.
    pub rounds_lost: u64,
    /// Series it will not measure, with why.
    pub refused: Vec<(u64, String)>,
}

#[derive(Debug, Default)]
struct Entry {
    status: AgentStatus,
    /// The current (or last) stream.
    stream: u64,
    /// A "disconnected" event went out for the current outage.
    down_reported: bool,
    revoked_reported: bool,
    clock: VecDeque<(f64, f64)>,
}

/// Shared by every agent stream.
#[derive(Debug, Default)]
pub struct Board {
    agents: Mutex<HashMap<String, Entry>>,
}

/// What a change on the board means for the event log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    None,
    /// First connection since the server started, or the first after a
    /// reported outage.
    Up,
    Down,
    ClockSkewed,
    ClockOk,
    Revoked,
}

impl Board {
    fn with<T>(&self, name: &str, f: impl FnOnce(&mut Entry) -> T) -> T {
        let mut map = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        let e = map.entry(name.to_string()).or_insert_with(|| Entry {
            status: AgentStatus {
                name: name.to_string(),
                ..AgentStatus::default()
            },
            // Never connected since the start: its first connection is
            // news, as after an outage.
            down_reported: true,
            ..Entry::default()
        });
        f(e)
    }

    pub fn snapshot(&self) -> Vec<AgentStatus> {
        let map = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        let mut v: Vec<AgentStatus> = map.values().map(|e| e.status.clone()).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn get(&self, name: &str) -> Option<AgentStatus> {
        let map = self.agents.lock().unwrap_or_else(PoisonError::into_inner);
        map.get(name).map(|e| e.status.clone())
    }

    /// A stream opened.
    #[allow(clippy::too_many_arguments)]
    pub fn connected(
        &self,
        name: &str,
        stream: u64,
        addr: SocketAddr,
        version: &str,
        os: &str,
        capabilities: &[String],
        now_ms: i64,
    ) -> Change {
        self.with(name, |e| {
            e.stream = stream;
            let s = &mut e.status;
            s.connected = true;
            s.addr = Some(addr);
            s.version = version.to_string();
            s.os = os.to_string();
            s.capabilities = capabilities.to_vec();
            s.connected_ms = Some(now_ms);
            s.last_seen_ms = Some(now_ms);
            s.refused.clear();
            // Offsets from an earlier stream may be stale.
            e.clock.clear();
            if std::mem::take(&mut e.down_reported) {
                Change::Up
            } else {
                Change::None
            }
        })
    }

    /// Stream `stream` ended. Ignored when a newer stream took over.
    pub fn disconnected(&self, name: &str, stream: u64, now_ms: i64) {
        self.with(name, |e| {
            if e.stream == stream {
                e.status.connected = false;
                e.status.last_seen_ms = Some(now_ms);
            }
        });
    }

    /// Whether the agent is still away since stream `stream` ended: then
    /// its outage is reported (once).
    pub fn still_down(&self, name: &str, stream: u64) -> Change {
        self.with(name, |e| {
            if e.stream == stream && !e.status.connected && !e.down_reported {
                e.down_reported = true;
                Change::Down
            } else {
                Change::None
            }
        })
    }

    /// The agent was refused as revoked; reported once per server run.
    pub fn revoked(&self, name: &str) -> Change {
        self.with(name, |e| {
            e.status.connected = false;
            // No "disconnected" event after a revocation.
            e.down_reported = true;
            if std::mem::replace(&mut e.revoked_reported, true) {
                Change::None
            } else {
                Change::Revoked
            }
        })
    }

    /// Any message from the agent.
    pub fn seen(&self, name: &str, now_ms: i64) {
        self.with(name, |e| e.status.last_seen_ms = Some(now_ms));
    }

    pub fn spool(&self, name: &str, bytes: u64, backlog: u64) {
        self.with(name, |e| {
            e.status.spool_bytes = Some(bytes);
            e.status.spool_backlog = Some(backlog);
        });
    }

    pub fn refused(&self, name: &str, refused: Vec<(u64, String)>) {
        self.with(name, |e| e.status.refused = refused);
    }

    pub fn rounds(&self, name: &str, timing: impl IntoIterator<Item = u8>, lost: u64) {
        self.with(name, |e| {
            e.status
                .timing
                .extend(timing.into_iter().filter(|&c| c != 0));
            e.status.rounds_lost += lost;
        });
    }

    /// A clock sample: `t1` server send, `t2` agent receive, `t3` agent
    /// send, `t4` server receive, all in microseconds. Returns whether
    /// the agent's skew flag changed, and the offset now taken (ms).
    pub fn clock(&self, name: &str, [t1, t2, t3, t4]: [i64; 4]) -> (Change, f64) {
        #[allow(clippy::cast_precision_loss)]
        let offset = ((t2 - t1) + (t3 - t4)) as f64 / 2000.0;
        #[allow(clippy::cast_precision_loss)]
        let delay = ((t4 - t1) - (t3 - t2)).max(0) as f64 / 1000.0;
        self.with(name, |e| {
            if e.clock.len() == CLOCK_SAMPLES {
                e.clock.pop_front();
            }
            e.clock.push_back((offset, delay));
            let (best, delay) = e
                .clock
                .iter()
                .copied()
                .min_by(|a, b| a.1.total_cmp(&b.1))
                .unwrap_or((offset, delay));
            let s = &mut e.status;
            s.clock_offset_ms = Some(best);
            s.clock_delay_ms = Some(delay);
            let skewed = best.abs() > CLOCK_LIMIT_MS;
            let change = match (s.clock_skewed, skewed) {
                (false, true) => Change::ClockSkewed,
                (true, false) => Change::ClockOk,
                _ => Change::None,
            };
            s.clock_skewed = skewed;
            (change, best)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "192.0.2.7:50000".parse().unwrap()
    }

    #[test]
    fn up_and_down_are_reported_once_per_outage() {
        let b = Board::default();
        assert_eq!(
            b.connected("genk", 1, addr(), "1", "linux", &[], 0),
            Change::Up
        );
        b.disconnected("genk", 1, 10);
        // Back within the grace time: nothing to report.
        assert_eq!(
            b.connected("genk", 2, addr(), "1", "linux", &[], 20),
            Change::None
        );
        b.disconnected("genk", 2, 30);
        assert_eq!(b.still_down("genk", 2), Change::Down);
        assert_eq!(b.still_down("genk", 2), Change::None);
        assert_eq!(
            b.connected("genk", 3, addr(), "1", "linux", &[], 99),
            Change::Up
        );
        // An old stream ending does not mark the new one down.
        b.disconnected("genk", 2, 100);
        assert!(b.get("genk").unwrap().connected);
        assert_eq!(b.still_down("genk", 2), Change::None);
    }

    #[test]
    fn the_lowest_delay_sample_sets_the_offset() {
        let b = Board::default();
        // Agent 150 ms ahead, 10 ms round trip.
        let (c, off) = b.clock("genk", [0, 155_000, 155_000, 10_000]);
        assert_eq!((c, off), (Change::ClockSkewed, 150.0));
        // A slow sample with a smaller offset does not win.
        let (c, off) = b.clock("genk", [0, 60_000, 60_000, 100_000]);
        assert_eq!((c, off), (Change::None, 150.0));
        // A faster one does.
        let (c, off) = b.clock("genk", [0, 2_000, 2_000, 2_000]);
        assert_eq!((c, off), (Change::ClockOk, 1.0));
        assert_eq!(b.get("genk").unwrap().clock_delay_ms, Some(2.0));
    }

    #[test]
    fn a_revoked_agent_is_not_reported_down() {
        let b = Board::default();
        b.connected("genk", 1, addr(), "1", "linux", &[], 0);
        assert_eq!(b.revoked("genk"), Change::Revoked);
        assert_eq!(b.revoked("genk"), Change::None);
        b.disconnected("genk", 1, 5);
        assert_eq!(b.still_down("genk", 1), Change::None);
    }
}
