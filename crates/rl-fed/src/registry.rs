//! Enrolled agents and pending tokens, as files in `<data_dir>/agents/`
//! (§21.7 G4).
//!
//! One file per agent (`agent-<name>.json`) and one per token
//! (`tokens/<sha256 of secret>.json`), so `routelith ctl agent` and a
//! running server never rewrite each other's files. A token is used up by
//! deleting its file, which only one caller can do.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{FedError, files, token};

/// Longest agent name, as for other names in the configuration.
pub const MAX_NAME_LEN: usize = 64;

/// Default lifetime of an enrollment token.
pub const TOKEN_TTL_MS: i64 = 24 * 3600 * 1000;

/// What the server knows about an enrolled agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRecord {
    pub name: String,
    /// SHA-256 (hex) of the agent's current certificate. Only this
    /// certificate is accepted; enrolling again replaces it.
    pub cert_sha256: String,
    pub enrolled_ms: i64,
    /// When the certificate expires.
    pub cert_expires_ms: i64,
    /// Agent version at enrollment.
    #[serde(default)]
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRecord {
    name: String,
    created_ms: i64,
    expires_ms: i64,
}

/// A token that has not been used yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingToken {
    pub name: String,
    pub expires_ms: i64,
}

/// The agents folder of one data directory.
#[derive(Debug, Clone)]
pub struct Registry {
    dir: PathBuf,
}

/// Agent names follow the rule for vantage names: 1 to 64 letters, digits,
/// '.', '_' or '-', starting with a letter or digit.
pub fn check_name(name: &str) -> Result<(), FedError> {
    let mut chars = name.chars();
    let ok = name.len() <= MAX_NAME_LEN
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(FedError::Invalid(format!(
            "agent name {name:?} must be 1 to {MAX_NAME_LEN} characters of letters, digits, \
             '.', '_' or '-', starting with a letter or digit"
        )))
    }
}

impl Registry {
    pub fn new(data_dir: &Path) -> Registry {
        Registry {
            dir: data_dir.join("agents"),
        }
    }

    fn agent_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("agent-{name}.json"))
    }

    fn tokens_dir(&self) -> PathBuf {
        self.dir.join("tokens")
    }

    /// Create a token for `name`, valid for `ttl_ms`. Returns its secret.
    /// Names that differ only in case are refused, because Windows and
    /// macOS file systems would mix up their files.
    pub fn add_token(&self, name: &str, ttl_ms: i64, now_ms: i64) -> Result<[u8; 32], FedError> {
        use ring::rand::SecureRandom;
        check_name(name)?;
        let known = self.list()?;
        let pending = self.pending_tokens(now_ms)?;
        let clash = known
            .iter()
            .map(|a| a.name.as_str())
            .chain(pending.iter().map(|t| t.name.as_str()))
            .find(|n| *n != name && n.eq_ignore_ascii_case(name));
        if let Some(other) = clash {
            return Err(FedError::Invalid(format!(
                "agent name {name:?} differs from {other:?} only in upper and lower case"
            )));
        }
        let mut secret = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| FedError::Invalid("no random numbers from the system".into()))?;
        let rec = TokenRecord {
            name: name.to_string(),
            created_ms: now_ms,
            expires_ms: now_ms.saturating_add(ttl_ms),
        };
        let body = serde_json::to_vec_pretty(&rec).map_err(json_err)?;
        files::write_private(
            &self
                .tokens_dir()
                .join(format!("{}.json", token::secret_id(&secret))),
            &body,
        )?;
        Ok(secret)
    }

    /// Use up a token: returns the agent name it was made for. A token
    /// works once, and not after it expired.
    pub fn claim_token(&self, secret: &[u8], now_ms: i64) -> Result<String, FedError> {
        let refused =
            || FedError::Refused("enrollment token unknown, already used or expired".into());
        let path = self
            .tokens_dir()
            .join(format!("{}.json", token::secret_id(secret)));
        let Some(body) = files::read_optional(&path)? else {
            return Err(refused());
        };
        // Whoever deletes the file owns the token.
        match std::fs::remove_file(&path) {
            Ok(()) => files::sync_dir(&self.tokens_dir()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(refused()),
            Err(e) => return Err(FedError::Io(format!("cannot remove {}", path.display()), e)),
        }
        let rec: TokenRecord = serde_json::from_slice(&body)
            .map_err(|e| FedError::Invalid(format!("{} is damaged: {e}", path.display())))?;
        if now_ms >= rec.expires_ms {
            return Err(refused());
        }
        check_name(&rec.name)?;
        Ok(rec.name)
    }

    /// Tokens not yet used or expired, oldest first. Expired token files
    /// are removed on the way.
    pub fn pending_tokens(&self, now_ms: i64) -> Result<Vec<PendingToken>, FedError> {
        let mut out = Vec::new();
        for (path, body) in self.json_files(&self.tokens_dir(), "")? {
            let Ok(rec) = serde_json::from_slice::<TokenRecord>(&body) else {
                continue;
            };
            if now_ms >= rec.expires_ms {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            out.push((
                rec.created_ms,
                PendingToken {
                    name: rec.name,
                    expires_ms: rec.expires_ms,
                },
            ));
        }
        out.sort_by_key(|(c, _)| *c);
        Ok(out.into_iter().map(|(_, t)| t).collect())
    }

    /// Save an agent's record (after enrollment or revocation).
    pub fn save(&self, rec: &AgentRecord) -> Result<(), FedError> {
        check_name(&rec.name)?;
        let body = serde_json::to_vec_pretty(rec).map_err(json_err)?;
        files::write_private(&self.agent_path(&rec.name), &body)
    }

    pub fn get(&self, name: &str) -> Result<Option<AgentRecord>, FedError> {
        check_name(name)?;
        let path = self.agent_path(name);
        match files::read_optional(&path)? {
            None => Ok(None),
            Some(b) => serde_json::from_slice(&b)
                .map(Some)
                .map_err(|e| FedError::Invalid(format!("{} is damaged: {e}", path.display()))),
        }
    }

    /// Every enrolled agent, by name.
    pub fn list(&self) -> Result<Vec<AgentRecord>, FedError> {
        let mut out: Vec<AgentRecord> = self
            .json_files(&self.dir, "agent-")?
            .into_iter()
            .filter_map(|(_, b)| serde_json::from_slice(&b).ok())
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The agent whose current certificate has this SHA-256, if any (also
    /// when revoked: the caller decides).
    pub fn find_by_cert(&self, cert_sha256: &[u8; 32]) -> Result<Option<AgentRecord>, FedError> {
        let hex = crate::hex(cert_sha256);
        Ok(self.list()?.into_iter().find(|a| a.cert_sha256 == hex))
    }

    /// Revoke an agent: its certificate is refused from now on, and
    /// enrolling again needs a new token. Returns false if there is no such
    /// agent.
    pub fn revoke(&self, name: &str, now_ms: i64) -> Result<bool, FedError> {
        let Some(mut rec) = self.get(name)? else {
            return Ok(false);
        };
        if rec.revoked_ms.is_none() {
            rec.revoked_ms = Some(now_ms);
            self.save(&rec)?;
        }
        Ok(true)
    }

    fn json_files(&self, dir: &Path, prefix: &str) -> Result<Vec<(PathBuf, Vec<u8>)>, FedError> {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(FedError::Io(format!("cannot read {}", dir.display()), e)),
        };
        let mut out = Vec::new();
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(n) = name.to_str() else { continue };
            if !n.starts_with(prefix) || !n.ends_with(".json") || n.starts_with('.') {
                continue;
            }
            if let Ok(Some(b)) = files::read_optional(&e.path()) {
                out.push((e.path(), b));
            }
        }
        Ok(out)
    }
}

fn json_err(e: serde_json::Error) -> FedError {
    FedError::Invalid(format!("cannot encode: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(name: &str, fp: u8) -> AgentRecord {
        AgentRecord {
            name: name.into(),
            cert_sha256: crate::hex(&[fp; 32]),
            enrolled_ms: 1,
            cert_expires_ms: 2,
            version: "0.0.0".into(),
            revoked_ms: None,
        }
    }

    #[test]
    fn a_token_works_once() {
        let d = tempfile::tempdir().unwrap();
        let r = Registry::new(d.path());
        let s = r.add_token("plant-genk", 1000, 0).unwrap();
        assert_eq!(r.pending_tokens(10).unwrap().len(), 1);
        assert_eq!(r.claim_token(&s, 10).unwrap(), "plant-genk");
        assert!(r.claim_token(&s, 10).is_err());
        assert!(r.pending_tokens(10).unwrap().is_empty());
    }

    #[test]
    fn an_expired_token_is_refused_and_tidied() {
        let d = tempfile::tempdir().unwrap();
        let r = Registry::new(d.path());
        let s = r.add_token("a", 1000, 0).unwrap();
        assert!(r.claim_token(&s, 1000).is_err());
        let _ = r.add_token("b", 1000, 0).unwrap();
        assert!(r.pending_tokens(5000).unwrap().is_empty());
        assert_eq!(std::fs::read_dir(r.tokens_dir()).unwrap().count(), 0);
    }

    #[test]
    fn unknown_secrets_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let r = Registry::new(d.path());
        assert!(r.claim_token(&[1; 32], 0).is_err());
    }

    #[test]
    fn the_secret_is_not_stored() {
        let d = tempfile::tempdir().unwrap();
        let r = Registry::new(d.path());
        let s = r.add_token("a", 1000, 0).unwrap();
        for e in std::fs::read_dir(r.tokens_dir()).unwrap() {
            let p = e.unwrap().path();
            let body = std::fs::read(&p).unwrap();
            let hex = crate::hex(&s);
            assert!(!String::from_utf8_lossy(&body).contains(&hex));
            assert!(!p.to_string_lossy().contains(&hex));
        }
    }

    #[test]
    fn names_are_checked() {
        let d = tempfile::tempdir().unwrap();
        let r = Registry::new(d.path());
        for bad in ["", "../x", "a/b", ".hidden", "a b", &"x".repeat(65)] {
            assert!(r.add_token(bad, 1000, 0).is_err(), "{bad:?}");
        }
        r.add_token("Genk", 1000, 0).unwrap();
        assert!(r.add_token("genk", 1000, 0).is_err());
        // The same name again is fine (a second token, e.g. to re-enroll).
        r.add_token("Genk", 1000, 0).unwrap();
    }

    #[test]
    fn agents_are_found_by_certificate_and_revoked() {
        let d = tempfile::tempdir().unwrap();
        let r = Registry::new(d.path());
        r.save(&rec("a", 1)).unwrap();
        r.save(&rec("b", 2)).unwrap();
        assert_eq!(r.list().unwrap().len(), 2);
        assert_eq!(r.find_by_cert(&[2; 32]).unwrap().unwrap().name, "b");
        assert!(r.find_by_cert(&[3; 32]).unwrap().is_none());
        assert!(r.revoke("b", 77).unwrap());
        assert_eq!(r.get("b").unwrap().unwrap().revoked_ms, Some(77));
        assert!(!r.revoke("c", 77).unwrap());
    }
}
