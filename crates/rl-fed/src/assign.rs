//! What the server asks an agent to measure (§21.7 G5) and the rounds that
//! come back (G7).

use std::collections::{HashMap, HashSet};

use rl_core::config::{Family, ProbeConfig, Schedule};
use rl_store::{ErrorCounts, StoredRound};
use serde::{Deserialize, Serialize};

use crate::FedError;
use crate::pb;

/// One series' settings, carried as JSON in [`pb::Assignment::spec_json`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    pub host: String,
    /// Never `Both`: a `both` target is two assignments.
    pub family: Family,
    pub schedule: Schedule,
    pub probe: ProbeConfig,
}

/// Build an assignment.
pub fn assignment(series_id: u64, target: &str, spec: &Spec) -> pb::Assignment {
    pb::Assignment {
        series_id,
        target: target.to_string(),
        family: spec.family.as_str().to_string(),
        // Serialising plain structs and enums cannot fail.
        spec_json: serde_json::to_vec(spec).unwrap_or_default(),
    }
}

/// Read an assignment's settings.
pub fn spec(a: &pb::Assignment) -> Result<Spec, FedError> {
    let s: Spec = serde_json::from_slice(&a.spec_json).map_err(|e| {
        FedError::Invalid(format!(
            "series {} ({}): settings this agent does not understand ({e}); \
             is the agent older than the server?",
            a.series_id, a.target
        ))
    })?;
    if s.family == Family::Both {
        return Err(FedError::Invalid(format!(
            "series {} ({}): family both is not one series",
            a.series_id, a.target
        )));
    }
    Ok(s)
}

/// A snapshot whose version is a digest of its assignments, so it changes
/// exactly when they do.
pub fn snapshot(mut assignments: Vec<pb::Assignment>) -> pb::ConfigSnapshot {
    use prost::Message;
    assignments.sort_by_key(|a| a.series_id);
    let mut bytes = Vec::new();
    for a in &assignments {
        a.encode_length_delimited(&mut bytes).unwrap_or_default();
    }
    pb::ConfigSnapshot {
        version: crate::hex(&crate::sha256(&bytes)[..8]),
        assignments,
    }
}

/// Every agent's snapshot, fixed while the server runs.
#[derive(Debug, Clone, Default)]
pub struct Assignments {
    by_agent: HashMap<String, (pb::ConfigSnapshot, HashSet<u64>)>,
}

impl Assignments {
    pub fn insert(&mut self, agent: &str, assignments: Vec<pb::Assignment>) {
        let ids = assignments.iter().map(|a| a.series_id).collect();
        self.by_agent
            .insert(agent.to_string(), (snapshot(assignments), ids));
    }

    /// The agent's snapshot; an empty one for an agent with nothing to do.
    pub fn snapshot(&self, agent: &str) -> pb::ConfigSnapshot {
        self.by_agent
            .get(agent)
            .map_or_else(|| snapshot(Vec::new()), |(s, _)| s.clone())
    }

    /// Whether `series` is one of the agent's.
    pub fn owns(&self, agent: &str, series: u64) -> bool {
        self.by_agent
            .get(agent)
            .is_some_and(|(_, ids)| ids.contains(&series))
    }

    pub fn agents(&self) -> impl Iterator<Item = &str> {
        self.by_agent.keys().map(String::as_str)
    }
}

/// A stored round as sent on the wire.
pub fn to_wire(
    seq: u64,
    series_id: u64,
    r: &StoredRound,
    http: Option<pb::HttpSummary>,
) -> pb::Round {
    pb::Round {
        seq,
        series_id,
        ts_ms: r.ts_ms,
        sent: u32::from(r.sent),
        rtts_us: r.rtts_us.clone(),
        unreachable: u32::from(r.errors.unreachable),
        time_exceeded: u32::from(r.errors.time_exceeded),
        send_failed: u32::from(r.errors.send_failed),
        other_errors: u32::from(r.errors.other),
        resolved: match r.resolved {
            None => Vec::new(),
            Some(std::net::IpAddr::V4(a)) => a.octets().to_vec(),
            Some(std::net::IpAddr::V6(a)) => a.octets().to_vec(),
        },
        timing: r.timing.map_or(0, |t| u32::from(t.code())),
        flags: u32::from(r.flags),
        http,
    }
}

/// A round from the wire, as the store keeps it. Out-of-range numbers are
/// refused here; the store checks the rest (ascending RTTs and so on).
pub fn from_wire(r: &pb::Round) -> Result<StoredRound, String> {
    let u16_of =
        |v: u32, what: &str| u16::try_from(v).map_err(|_| format!("{what} {v} is too large"));
    let resolved = match r.resolved.len() {
        0 => None,
        4 => {
            let b: [u8; 4] = r.resolved[..].try_into().map_err(|_| "address")?;
            Some(std::net::IpAddr::from(b))
        }
        16 => {
            let b: [u8; 16] = r.resolved[..].try_into().map_err(|_| "address")?;
            Some(std::net::IpAddr::from(b))
        }
        n => return Err(format!("an address of {n} bytes")),
    };
    let timing = match r.timing {
        0 => None,
        t => {
            let code = u8::try_from(t).map_err(|_| format!("timing {t}"))?;
            Some(rl_core::TimingBackend::from_code(code).ok_or_else(|| format!("timing {t}"))?)
        }
    };
    Ok(StoredRound {
        ts_ms: r.ts_ms,
        sent: u16_of(r.sent, "sent")?,
        rtts_us: r.rtts_us.clone(),
        errors: ErrorCounts {
            unreachable: u16_of(r.unreachable, "unreachable")?,
            time_exceeded: u16_of(r.time_exceeded, "time_exceeded")?,
            send_failed: u16_of(r.send_failed, "send_failed")?,
            other: u16_of(r.other_errors, "other_errors")?,
        },
        resolved,
        timing,
        flags: u8::try_from(r.flags).map_err(|_| format!("flags {}", r.flags))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn spec() -> Spec {
        Spec {
            host: "192.0.2.1".into(),
            family: Family::V4,
            schedule: Schedule {
                step: Duration::from_secs(300),
                pings: 20,
                spread: Duration::from_secs(20),
                timeout: Duration::from_secs(2),
            },
            probe: ProbeConfig::Icmp { payload_size: 56 },
        }
    }

    #[test]
    fn a_spec_survives_the_trip() {
        let a = assignment(7, "gw", &spec());
        assert_eq!(a.family, "v4");
        assert_eq!(super::spec(&a).unwrap(), spec());
    }

    #[test]
    fn the_version_follows_the_assignments() {
        let a = assignment(1, "a", &spec());
        let b = assignment(2, "b", &spec());
        let v1 = snapshot(vec![a.clone(), b.clone()]).version;
        assert_eq!(snapshot(vec![b.clone(), a.clone()]).version, v1);
        assert_ne!(snapshot(vec![a]).version, v1);
        assert_ne!(snapshot(Vec::new()).version, v1);
    }

    #[test]
    fn assignments_know_their_series() {
        let mut m = Assignments::default();
        m.insert("genk", vec![assignment(3, "a", &spec())]);
        assert!(m.owns("genk", 3));
        assert!(!m.owns("genk", 4));
        assert!(!m.owns("gent", 3));
        assert!(m.snapshot("gent").assignments.is_empty());
    }

    #[test]
    fn rounds_survive_the_wire() {
        let r = StoredRound {
            ts_ms: 1_700_000_000_000,
            sent: 3,
            rtts_us: vec![10, 20],
            errors: ErrorCounts {
                unreachable: 1,
                ..ErrorCounts::default()
            },
            resolved: Some("2001:db8::1".parse().unwrap()),
            timing: Some(rl_core::TimingBackend::from_code(1).unwrap()),
            flags: 1,
        };
        let w = to_wire(5, 9, &r, None);
        assert_eq!((w.seq, w.series_id), (5, 9));
        assert_eq!(from_wire(&w).unwrap(), r);
        let mut bad = w.clone();
        bad.sent = 70_000;
        assert!(from_wire(&bad).is_err());
        let mut bad = w;
        bad.resolved = vec![1, 2, 3];
        assert!(from_wire(&bad).is_err());
    }
}
