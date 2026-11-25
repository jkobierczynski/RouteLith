//! Enrollment tokens (§21.7 G4).
//!
//! A token is `rlt1-` followed by base64url of 64 bytes: a 32-byte random
//! secret and the SHA-256 fingerprint of the server's CA certificate. The
//! agent sends only the secret, and trusts the server it reaches only if
//! the server shows that CA. The server keeps only the secret's hash.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::FedError;

const PREFIX: &str = "rlt1-";

/// A parsed enrollment token.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    pub secret: [u8; 32],
    pub ca_sha256: [u8; 32],
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("secret", &"…")
            .field("ca_sha256", &crate::hex(&self.ca_sha256))
            .finish()
    }
}

impl Token {
    /// The text people copy to the agent.
    pub fn encode(&self) -> String {
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&self.secret);
        raw[32..].copy_from_slice(&self.ca_sha256);
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw))
    }

    pub fn parse(s: &str) -> Result<Token, FedError> {
        let bad = || {
            FedError::Invalid(
                "not an enrollment token (it starts with rlt1-; copy it whole from \
                 `routelith ctl agent add`)"
                    .into(),
            )
        };
        let body = s.trim().strip_prefix(PREFIX).ok_or_else(bad)?;
        let raw = URL_SAFE_NO_PAD.decode(body).map_err(|_| bad())?;
        if raw.len() != 64 {
            return Err(bad());
        }
        let mut secret = [0; 32];
        let mut ca_sha256 = [0; 32];
        secret.copy_from_slice(&raw[..32]);
        ca_sha256.copy_from_slice(&raw[32..]);
        Ok(Token { secret, ca_sha256 })
    }
}

/// The name under which the server stores a token: hex of the secret's
/// SHA-256, so the secret itself is never on the server's disk.
pub fn secret_id(secret: &[u8]) -> String {
    crate::hex(&crate::sha256(secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_survives_encoding() {
        let t = Token {
            secret: [7; 32],
            ca_sha256: [9; 32],
        };
        let s = t.encode();
        assert!(s.starts_with("rlt1-"));
        assert_eq!(s.len(), 5 + 86);
        assert_eq!(Token::parse(&s).unwrap(), t);
        assert_eq!(Token::parse(&format!("  {s}\n")).unwrap(), t);
    }

    #[test]
    fn other_text_is_not_a_token() {
        for s in ["", "rlt1-", "rlt2-AAAA", "rlt1-!!!!", "rlt1-AAAA"] {
            assert!(Token::parse(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn debug_hides_the_secret() {
        let t = Token {
            secret: [0xab; 32],
            ca_sha256: [1; 32],
        };
        assert!(!format!("{t:?}").contains("abab"));
    }
}
