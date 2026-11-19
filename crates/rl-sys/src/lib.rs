//! All unsafe and OS FFI: ping sockets, Windows ICMP API, timestamps, host
//! health readings, service glue.
//!
//! This is the only crate in the workspace allowed to contain `unsafe`.
//! Every `unsafe` block must carry a `// SAFETY:` comment
//! (enforced by `clippy::undocumented_unsafe_blocks`).

pub mod host;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub mod service;
