//! Domain types: targets, rounds, samples, config schema and errors.
#![forbid(unsafe_code)]

pub mod addr;
pub mod alert;
pub mod config;
pub mod duration;
pub mod mos;
pub mod output;
pub mod round;
pub mod secret;
pub mod silence;
pub mod stats;
pub mod timing;

pub use round::{
    HttpRound, PhaseTimings, ProbeMeta, ResolvedTarget, RoundPlan, RoundResult, Sample, SampleError,
};
pub use stats::RoundStats;
pub use timing::{TimingBackend, TimingSource};
