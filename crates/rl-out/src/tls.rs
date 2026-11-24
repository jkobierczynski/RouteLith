//! The TLS client for syslog over TLS (RFC 5425) and HTTPS webhooks.

use std::path::Path;
use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// System roots plus `ca_file`; a client certificate when both
/// `cert_file` and `key_file` are given.
pub(crate) fn client_config(
    ca_file: Option<&Path>,
    cert_file: Option<&Path>,
    key_file: Option<&Path>,
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup: {e}"))?;
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    let (added, _) = roots.add_parsable_certificates(native.certs);
    if let Some(path) = ca_file {
        let certs = certs(path, "ca_file")?;
        let (ok, bad) = roots.add_parsable_certificates(certs);
        if ok == 0 {
            return Err(format!(
                "ca_file {}: {bad} certificate(s), none usable",
                path.display()
            ));
        }
    } else if added == 0 {
        return Err(
            "no trusted CA certificates: the system store is empty or unreadable; set ca_file"
                .into(),
        );
    }
    let builder = builder.with_root_certificates(roots);
    let config = match (cert_file, key_file) {
        (Some(c), Some(k)) => {
            let chain = certs(c, "cert_file")?;
            let key = PrivateKeyDer::from_pem_file(k)
                .map_err(|e| format!("key_file {}: {e}", k.display()))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| format!("cert_file and key_file: {e}"))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => return Err("cert_file and key_file go together".into()),
    };
    Ok(Arc::new(config))
}

pub(crate) fn certs(path: &Path, key: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("{key} {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{key} {}: no certificates found", path.display()));
    }
    Ok(certs)
}
