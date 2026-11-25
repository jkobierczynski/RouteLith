//! What the server has stored from each agent (§21.7 G7): per agent, its
//! spool id and the highest seq stored, in `data_dir/agents.json`. Rounds
//! at or below that seq are replays and are dropped.
//!
//! The store also drops a round that is not newer than its series' last
//! one, so a mark lost in a crash (the file is written after the rounds
//! are synced) still lets no duplicate in.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::{FedError, files};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Mark {
    /// The agent's spool id, hex (JSON numbers lose precision past 2^53).
    #[serde(with = "hex_u64")]
    spool: u64,
    /// Highest seq of that spool stored.
    seq: u64,
}

mod hex_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{v:016x}"))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        u64::from_str_radix(&s, 16).map_err(serde::de::Error::custom)
    }
}

/// The high-water marks, shared by every agent stream.
#[derive(Debug)]
pub struct Seen {
    path: PathBuf,
    marks: Mutex<HashMap<String, Mark>>,
    /// One lock per agent, held while a batch is stored, so two streams of
    /// the same agent (one replacing the other) cannot interleave.
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl Seen {
    /// Read `data_dir/agents.json`. An unreadable file is reported and
    /// treated as empty: the store still drops duplicates.
    pub fn load(data_dir: &Path) -> (Seen, Option<String>) {
        let path = data_dir.join("agents.json");
        let (marks, warning) = match files::read_optional(&path) {
            Ok(None) => (HashMap::new(), None),
            Ok(Some(b)) => match serde_json::from_slice(&b) {
                Ok(m) => (m, None),
                Err(e) => (
                    HashMap::new(),
                    Some(format!("{}: {e}; starting without it", path.display())),
                ),
            },
            Err(e) => (HashMap::new(), Some(format!("{e}; starting without it"))),
        };
        (
            Seen {
                path,
                marks: Mutex::new(marks),
                locks: Mutex::new(HashMap::new()),
            },
            warning,
        )
    }

    /// The highest seq stored from `agent`'s spool `spool` (0 if none).
    pub fn stored(&self, agent: &str, spool: u64) -> u64 {
        self.marks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(agent)
            .filter(|m| m.spool == spool)
            .map_or(0, |m| m.seq)
    }

    pub fn lock(&self, agent: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(agent.to_string())
            .or_default()
            .clone()
    }

    /// Everything up to `seq` of `agent`'s spool `spool` is stored. Blocks
    /// on the file write.
    pub fn record(&self, agent: &str, spool: u64, seq: u64) -> Result<(), FedError> {
        let body = {
            let mut marks = self.marks.lock().unwrap_or_else(PoisonError::into_inner);
            let m = marks.entry(agent.to_string()).or_default();
            if m.spool == spool && m.seq >= seq {
                return Ok(());
            }
            if m.spool != spool {
                *m = Mark { spool, seq: 0 };
            }
            m.seq = seq;
            let sorted: std::collections::BTreeMap<_, _> = marks.iter().collect();
            serde_json::to_vec_pretty(&sorted)
                .map_err(|e| FedError::Invalid(format!("agents.json: {e}")))?
        };
        files::write_private(&self.path, &body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_persist_per_spool() {
        let tmp = tempfile::tempdir().unwrap();
        let (seen, w) = Seen::load(tmp.path());
        assert!(w.is_none());
        assert_eq!(seen.stored("genk", 0xabc), 0);
        seen.record("genk", 0xabc, 10).unwrap();
        seen.record("genk", 0xabc, 5).unwrap();
        seen.record("hasselt", 1, 3).unwrap();
        let (seen, _) = Seen::load(tmp.path());
        assert_eq!(seen.stored("genk", 0xabc), 10);
        assert_eq!(seen.stored("genk", 0xdef), 0, "another spool starts over");
        seen.record("genk", 0xdef, 2).unwrap();
        assert_eq!(seen.stored("genk", 0xabc), 0);
        assert_eq!(seen.stored("hasselt", 1), 3);
    }

    #[test]
    fn a_damaged_file_is_reported_and_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("agents.json"), b"{nope").unwrap();
        let (seen, w) = Seen::load(tmp.path());
        assert!(w.is_some());
        assert_eq!(seen.stored("genk", 1), 0);
    }
}
