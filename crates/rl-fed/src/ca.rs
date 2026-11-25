//! The server's own certificate authority (§21.7 G3).
//!
//! Created on first use in `<data_dir>/ca/`: `ca.pem` (the certificate,
//! public) and `ca.key` (the private key, owner-only on Unix). It signs a
//! fresh server certificate at every start and one client certificate per
//! enrolled agent.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateSigningRequestDer, PrivateKeyDer};

use crate::{FedError, SERVER_NAME, files};

const CA_YEARS: u64 = 10;
/// Agent and server certificates.
pub const LEAF_DAYS: u64 = 365;
/// Certificates start an hour in the past, so a clock that is a little
/// behind does not reject a certificate that was just made.
const BACKDATE: Duration = Duration::from_secs(3600);
const DAY: Duration = Duration::from_secs(86_400);

/// A loaded CA.
pub struct Ca {
    cert_der: CertificateDer<'static>,
    key: KeyPair,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("sha256", &crate::hex(&self.fingerprint()))
            .finish_non_exhaustive()
    }
}

/// The CA folder inside a data directory.
pub fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join("ca")
}

impl Ca {
    /// Load the CA in `data_dir`, creating it if there is none yet.
    pub fn load_or_create(data_dir: &Path) -> Result<Ca, FedError> {
        if let Some(ca) = Ca::load(data_dir)? {
            return Ok(ca);
        }
        let dir = dir(data_dir);
        // Build the whole CA in a side folder and rename it into place, so
        // a server and `ctl agent add` starting together cannot end up with
        // a key from one and a certificate from the other.
        let tmp = data_dir.join(format!(".ca-{}.tmp", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let (cert_pem, key_pem) = new_ca()?;
        files::write_private(&tmp.join("ca.key"), key_pem.as_bytes())?;
        files::write_private(&tmp.join("ca.pem"), cert_pem.as_bytes())?;
        match std::fs::rename(&tmp, &dir) {
            Ok(()) => files::sync_dir(data_dir),
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tmp);
                // Someone else made it first: use theirs.
                if let Some(ca) = Ca::load(data_dir)? {
                    return Ok(ca);
                }
                return Err(FedError::Io(format!("cannot create {}", dir.display()), e));
            }
        }
        Ca::load(data_dir)?
            .ok_or_else(|| FedError::Invalid(format!("{} vanished after creation", dir.display())))
    }

    /// Load the CA in `data_dir`, `None` if there is none.
    pub fn load(data_dir: &Path) -> Result<Option<Ca>, FedError> {
        let dir = dir(data_dir);
        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca.key");
        let Some(cert_pem) = files::read_optional(&cert_path)? else {
            return Ok(None);
        };
        let key_pem = files::read_optional(&key_path)?.ok_or_else(|| {
            FedError::Invalid(format!(
                "{} exists but {} does not",
                cert_path.display(),
                key_path.display()
            ))
        })?;
        let cert_der = CertificateDer::from_pem_slice(&cert_pem).map_err(|e| {
            FedError::Invalid(format!(
                "{} is not a PEM certificate: {e}",
                cert_path.display()
            ))
        })?;
        let key_pem = String::from_utf8(key_pem)
            .map_err(|_| FedError::Invalid(format!("{} is not PEM", key_path.display())))?;
        let key = KeyPair::from_pem(&key_pem).map_err(|e| {
            FedError::Invalid(format!("{} is not a usable key: {e}", key_path.display()))
        })?;
        Ok(Some(Ca { cert_der, key }))
    }

    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// SHA-256 of the CA certificate: what enrollment tokens carry.
    pub fn fingerprint(&self) -> [u8; 32] {
        crate::sha256(&self.cert_der)
    }

    fn issuer(&self) -> Result<Issuer<'static, &KeyPair>, FedError> {
        Issuer::from_ca_cert_der(&self.cert_der, &self.key)
            .map_err(|e| FedError::Invalid(format!("cannot use the CA certificate: {e}")))
    }

    /// A new server certificate and key, for this run of the server.
    /// Returns the chain (server certificate, then the CA) and the key.
    pub fn server_identity(
        &self,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), FedError> {
        let key = KeyPair::generate().map_err(cert_err)?;
        let mut p = leaf_params(SERVER_NAME)?;
        p.subject_alt_names = vec![SanType::DnsName(SERVER_NAME.try_into().map_err(cert_err)?)];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = p.signed_by(&key, &self.issuer()?).map_err(cert_err)?;
        let key_der = PrivateKeyDer::try_from(key.serialize_der())
            .map_err(|e| FedError::Invalid(format!("cannot encode the server key: {e}")))?;
        Ok((vec![cert.der().clone(), self.cert_der.clone()], key_der))
    }

    /// Sign an agent's certificate request. Everything the request asks for
    /// is ignored except its public key: the certificate names `name` and
    /// can only authenticate a client.
    pub fn sign_agent(
        &self,
        csr_der: &[u8],
        name: &str,
    ) -> Result<CertificateDer<'static>, FedError> {
        let csr = CertificateSigningRequestDer::from(csr_der);
        let mut req = CertificateSigningRequestParams::from_der(&csr).map_err(|e| {
            FedError::Invalid(format!("the agent's certificate request is not valid: {e}"))
        })?;
        let mut p = leaf_params(name)?;
        p.subject_alt_names = vec![SanType::URI(agent_uri(name).try_into().map_err(cert_err)?)];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        req.params = p;
        let cert = req.signed_by(&self.issuer()?).map_err(cert_err)?;
        Ok(cert.der().clone())
    }
}

/// The URI an agent certificate carries in its subject alternative name.
pub fn agent_uri(name: &str) -> String {
    format!("urn:routelith:agent:{name}")
}

fn new_ca() -> Result<(String, String), FedError> {
    let key = KeyPair::generate().map_err(cert_err)?;
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Routelith agent CA");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = SystemTime::now();
    p.not_before = (now - BACKDATE).into();
    p.not_after = (now + DAY * (365 * CA_YEARS as u32 + 3)).into();
    p.serial_number = Some(random_serial()?);
    let cert = p.self_signed(&key).map_err(cert_err)?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn leaf_params(common_name: &str) -> Result<CertificateParams, FedError> {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    p.distinguished_name = dn;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.use_authority_key_identifier_extension = true;
    let now = SystemTime::now();
    p.not_before = (now - BACKDATE).into();
    p.not_after = (now + DAY * LEAF_DAYS as u32).into();
    p.serial_number = Some(random_serial()?);
    Ok(p)
}

fn random_serial() -> Result<SerialNumber, FedError> {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| FedError::Invalid("no random numbers from the system".into()))?;
    // Positive and never zero-length after DER's leading-zero trimming.
    b[0] = (b[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&b))
}

fn cert_err(e: rcgen::Error) -> FedError {
    FedError::Invalid(format!("certificate error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    #[test]
    fn the_ca_is_created_once_and_reloaded() {
        let d = tempfile::tempdir().unwrap();
        assert!(Ca::load(d.path()).unwrap().is_none());
        let a = Ca::load_or_create(d.path()).unwrap();
        let b = Ca::load_or_create(d.path()).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir(d.path()).join("ca.key")).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn an_agent_certificate_ignores_what_the_request_asks_for() {
        let d = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(d.path()).unwrap();
        let key = KeyPair::generate().unwrap();
        // The request asks to be the server; it must not get that.
        let mut want = CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
        want.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let csr = want.serialize_request(&key).unwrap();
        let cert = ca.sign_agent(csr.der(), "plant-genk").unwrap();
        let roots = crate::tls::roots(ca.cert_der()).unwrap();
        // It works as a client certificate...
        let v = rustls::server::WebPkiClientVerifier::builder_with_provider(
            roots.clone().into(),
            crate::tls::provider(),
        )
        .build()
        .unwrap();
        v.verify_client_cert(&cert, &[], rustls_pki_types::UnixTime::now())
            .unwrap();
        // ...but not as the server.
        let s = rustls::client::WebPkiServerVerifier::builder_with_provider(
            roots.into(),
            crate::tls::provider(),
        )
        .build()
        .unwrap();
        let name = rustls_pki_types::ServerName::try_from(SERVER_NAME).unwrap();
        assert!(
            s.verify_server_cert(&cert, &[], &name, &[], rustls_pki_types::UnixTime::now())
                .is_err()
        );
    }

    #[test]
    fn garbage_is_not_a_certificate_request() {
        let d = tempfile::tempdir().unwrap();
        let ca = Ca::load_or_create(d.path()).unwrap();
        assert!(ca.sign_agent(b"nonsense", "a").is_err());
    }
}
