//! Domain types: targets, rounds, samples, config schema and errors.
#![forbid(unsafe_code)]

pub mod round;
pub mod stats;
pub mod timing;

pub use round::{ProbeMeta, ResolvedTarget, RoundPlan, RoundResult, Sample, SampleError};
pub use stats::RoundStats;
pub use timing::{TimingBackend, TimingSource};
