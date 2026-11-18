//! smokestore: WAL, day segments, codecs and (later) rollups.
//!
//! M0 has the raw tier only (architecture doc §6, decision D6): every round
//! is kept at full resolution in one segment file per series and UTC day,
//! with a WAL for crash safety and the series index in `meta.redb`.
//!
//! ```no_run
//! # use rl_store::*;
//! # fn demo(dir: &std::path::Path, round: StoredRound, now_ms: i64) -> Result<(), StoreError> {
//! let (mut w, _recovery) = Writer::open(dir, WriterOptions::default(), now_ms)?;
//! let [id] = w.register(&[SeriesKey::new("local", "gateway", "v4")])?[..] else { unreachable!() };
//! w.append(id, round)?;
//! w.sync()?; // about once a second
//! w.close()?;
//!
//! let r = Reader::open(dir)?;
//! let rounds = r.read(id, 0, now_ms)?;
//! # Ok(()) }
//! ```
#![forbid(unsafe_code)]

mod codec;
mod index;
pub mod layout;
mod reader;
mod round;
mod segment;
mod varint;
mod wal;
mod writer;

use std::path::PathBuf;

pub use index::SeriesKey;
pub use reader::{Reader, VerifyReport};
pub use round::{ErrorCounts, FLAG_CLOCK_STEP, StoredRound};
pub use writer::{Appended, Recovery, Writer, WriterOptions, WriterStats};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("series index: {0}")]
    Index(String),
    #[error("{}: {reason}", path.display())]
    Corrupt { path: PathBuf, reason: String },
    #[error("invalid round: {0}")]
    InvalidRound(&'static str),
}
