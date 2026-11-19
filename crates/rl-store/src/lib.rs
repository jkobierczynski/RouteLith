//! smokestore: WAL, day segments, codecs and rollups.
//!
//! Every round is kept at full resolution in one segment file per series
//! and UTC day, with a WAL for crash safety and the series index in
//! `meta.redb` (architecture doc §6, decision D6). When a day is sealed its
//! rounds are consolidated into hourly and daily rollup points that keep
//! the distribution (§6.4), and retention deletes whole files per tier.
//!
//! ```no_run
//! # use rl_store::*;
//! # fn demo(dir: &std::path::Path, round: StoredRound, now_ms: i64) -> Result<(), StoreError> {
//! let (mut w, _recovery) = Writer::open(dir, WriterOptions::default(), now_ms)?;
//! let [id] = w.register(&[SeriesKey::new("local", "gateway", "v4")])?[..] else { unreachable!() };
//! match w.append(id, round)? {
//!     Appended::Stored => {}
//!     // Not newer than the series' last round (a duplicate or a late one).
//!     Appended::Late => eprintln!("round dropped as late"),
//! }
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
mod rollup;
mod round;
mod segment;
mod varint;
mod wal;
mod writer;

use std::path::PathBuf;

pub use index::SeriesKey;
pub use reader::{Reader, Resolution, VerifyReport};
pub use rollup::{QUANTILES, RollupPoint, Tier, quantiles};
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
    #[error("series key {0:?} contains the control character U+001F")]
    InvalidKey(String),
    #[error("invalid writer options: {0}")]
    InvalidOptions(&'static str),
    #[error("{} is already open by another writer", .0.display())]
    Locked(PathBuf),
    /// An earlier write failed; reopen the directory to recover.
    #[error("store stopped after an earlier error ({0}); restart to recover")]
    Stopped(String),
    /// Retention deleted a segment while it was being read; reading again
    /// finds its day in the rollups.
    #[error("{} was deleted by retention during the read", .0.display())]
    Expired(PathBuf),
}
