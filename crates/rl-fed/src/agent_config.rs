//! The agent's configuration file (§21.7 G1). It never lists targets:
//! those come from the server.
//!
//! ```toml
//! server   = "monitor.example.be:4443"
//! data_dir = "/var/lib/routelith-agent"
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::FedError;
use crate::client::ServerAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub server: ServerAddr,
    /// Identity (key, certificate, pinned CA) and, from M3 step 3, the spool.
    pub data_dir: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    server: String,
    data_dir: String,
}

impl AgentConfig {
    pub fn parse(src: &str) -> Result<AgentConfig, FedError> {
        let raw: Raw = toml::from_str(src).map_err(|e| FedError::Invalid(e.to_string()))?;
        if raw.data_dir.trim().is_empty() || raw.data_dir.contains('\0') {
            return Err(FedError::Invalid("data_dir must be a folder path".into()));
        }
        Ok(AgentConfig {
            server: ServerAddr::parse(&raw.server)?,
            data_dir: PathBuf::from(raw.data_dir),
        })
    }

    pub fn load(path: &Path) -> Result<AgentConfig, FedError> {
        let src = std::fs::read_to_string(path)
            .map_err(FedError::io(format!("cannot read {}", path.display())))?;
        AgentConfig::parse(&src).map_err(|e| FedError::Invalid(format!("{}: {e}", path.display())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_agent_config() {
        let c =
            AgentConfig::parse("server = \"mon.example.be\"\ndata_dir = \"/var/lib/a\"\n").unwrap();
        assert_eq!(c.server.port, crate::DEFAULT_PORT);
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/a"));
    }

    #[test]
    fn mistakes_are_reported() {
        assert!(AgentConfig::parse("server = \"x\"\n").is_err());
        assert!(AgentConfig::parse("server = \"x\"\ndata_dir = \"d\"\ntargets = 1\n").is_err());
        assert!(AgentConfig::parse("server = \"x:0\"\ndata_dir = \"d\"\n").is_err());
        assert!(AgentConfig::parse("server = \"x\"\ndata_dir = \"\"\n").is_err());
    }
}
