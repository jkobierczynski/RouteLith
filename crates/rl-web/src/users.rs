//! UI users (doc §21.5 F11): a TOML file of names, roles and Argon2id
//! password hashes, written by `routelith ctl user` and read by the
//! server, which notices when it changes.
//!
//! ```toml
//! [[user]]
//! name = "jurgen"
//! role = "admin"
//! password = "$argon2id$v=19$m=19456,t=2,p=1$..."
//! ```

use std::fmt;
use std::io::Write;
use std::path::Path;

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

/// The shortest password `ctl user` takes.
pub const MIN_PASSWORD: usize = 10;

/// What a user may do. Each role can do everything the one before it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Reads graphs, alerts and events.
    Viewer,
    /// Also silences alerts.
    Operator,
    /// Everything.
    Admin,
}

impl Role {
    pub const NAMES: [&'static str; 3] = ["viewer", "operator", "admin"];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "viewer" => Some(Role::Viewer),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One user as the file holds it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub role: Role,
    /// The PHC string of the Argon2id hash.
    pub password: String,
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("name", &self.name)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// The users file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Users {
    #[serde(default, rename = "user")]
    pub users: Vec<User>,
}

const HEADER: &str = "# Routelith UI users. Change them with `routelith ctl user`;\n\
                      # the server picks up changes without a restart.\n\n";

impl Users {
    /// Read `path`; a missing file is an empty list.
    pub fn load(path: &Path) -> Result<Users, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Users::default()),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let users: Users = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut seen = std::collections::HashSet::new();
        for u in &users.users {
            check_name(&u.name).map_err(|e| format!("{}: {e}", path.display()))?;
            if !seen.insert(u.name.as_str()) {
                return Err(format!(
                    "{}: user {:?} is listed twice",
                    path.display(),
                    u.name
                ));
            }
            PasswordHash::new(&u.password).map_err(|e| {
                format!(
                    "{}: user {:?}: password is not a valid hash: {e}",
                    path.display(),
                    u.name
                )
            })?;
        }
        Ok(users)
    }

    /// Write the file whole, readable by its owner only, replacing the old
    /// one in a single step.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let body = toml::to_string(self).map_err(|e| format!("cannot write users: {e}"))?;
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path
            .file_name()
            .ok_or_else(|| format!("{} is not a file name", path.display()))?;
        // The data directory may not exist before the server first ran.
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let write = || -> std::io::Result<()> {
            let mut f = opts.open(&tmp)?;
            f.write_all(HEADER.as_bytes())?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, path)
        };
        write().map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("cannot write {}: {e}", path.display())
        })
    }

    pub fn get(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.name == name)
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

/// A user name: 1 to 64 letters, digits and `.`, `_`, `-` or `@`.
pub fn check_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "user name {name:?} must be 1 to 64 letters, digits, '.', '_', '-' or '@'"
        ))
    }
}

/// The Argon2id hash of `password`, with a fresh random salt and the
/// crate's default cost (19 MiB, 2 passes, OWASP's recommendation).
pub fn hash_password(password: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| "no random numbers from the system".to_string())?;
    Argon2::default()
        .hash_password_with_salt(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("cannot hash the password: {e}"))
}

/// Whether `password` matches the PHC string `hash`. Slow on purpose.
pub fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}

/// A hash of no one's password, checked when the name is unknown so an
/// unknown name takes as long to refuse as a wrong password.
pub(crate) fn dummy_hash() -> &'static str {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DUMMY.get_or_init(|| hash_password("routelith-no-such-user").unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hash written by argon2 0.5 (RouteLith before the 0.6 upgrade)
    /// must still verify, so existing users files keep working.
    #[test]
    fn hashes_from_argon2_0_5_still_verify() {
        let old = "$argon2id$v=19$m=19456,t=2,p=1$BwcHBwcHBwcHBwcHBwcHBw$WLRGUa13/B3MXznFse33FId4O++DaYL6ulYUMEhpRqE";
        assert!(verify_password(old, "correct horse battery"));
        assert!(!verify_password(old, "wrong horse battery"));
    }

    #[test]
    fn new_hashes_round_trip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password(&h, "correct horse battery"));
        assert!(!verify_password(&h, "wrong horse battery"));
    }
}
