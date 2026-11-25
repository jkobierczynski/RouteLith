//! TLS settings for the agent link: TLS 1.3 only, ring, ALPN h2.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use crate::FedError;

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(crate) fn roots(ca: &CertificateDer<'_>) -> Result<RootCertStore, FedError> {
    let mut r = RootCertStore::empty();
    r.add(ca.clone().into_owned())
        .map_err(|e| FedError::Invalid(format!("the CA certificate is not usable: {e}")))?;
    Ok(r)
}

fn tls_err(e: rustls::Error) -> FedError {
    FedError::Invalid(format!("TLS setup: {e}"))
}

/// The server side: a client certificate is optional at the TLS level
/// (enrollment comes without one) and required by the Connect call.
pub(crate) fn server_config(
    ca: &CertificateDer<'_>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, FedError> {
    let clients = WebPkiClientVerifier::builder_with_provider(roots(ca)?.into(), provider())
        .allow_unauthenticated()
        .build()
        .map_err(|e| FedError::Invalid(format!("TLS setup: {e}")))?;
    let mut c = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .with_client_cert_verifier(clients)
        .with_single_cert(chain, key)
        .map_err(tls_err)?;
    c.alpn_protocols = vec![b"h2".to_vec()];
    Ok(c)
}

/// The agent side after enrollment: trust only the pinned CA, show the
/// agent's own certificate.
pub(crate) fn client_config(
    ca: &CertificateDer<'_>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ClientConfig, FedError> {
    let mut c = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .with_root_certificates(roots(ca)?)
        .with_client_auth_cert(vec![cert], key)
        .map_err(tls_err)?;
    c.alpn_protocols = vec![b"h2".to_vec()];
    Ok(c)
}

/// The agent side while enrolling: it has no CA certificate yet, only the
/// CA's fingerprint from the token.
pub(crate) fn enroll_config(ca_sha256: [u8; 32]) -> Result<rustls::ClientConfig, FedError> {
    let mut c = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCa { ca_sha256 }))
        .with_no_client_auth();
    c.alpn_protocols = vec![b"h2".to_vec()];
    Ok(c)
}

/// Accepts a server whose chain contains the CA with the given fingerprint
/// and whose certificate that CA signed for [`crate::SERVER_NAME`]; the
/// usual checks (dates, key usage, name) then run against that CA.
#[derive(Debug)]
struct PinnedCa {
    ca_sha256: [u8; 32],
}

impl ServerCertVerifier for PinnedCa {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ca = intermediates
            .iter()
            .find(|c| crate::sha256(c) == self.ca_sha256)
            .ok_or_else(|| {
                rustls::Error::General(
                    "the server's CA does not match the enrollment token (wrong server, \
                     or its CA was replaced)"
                        .into(),
                )
            })?;
        let roots = roots(ca).map_err(|e| rustls::Error::General(e.to_string()))?;
        WebPkiServerVerifier::builder_with_provider(roots.into(), provider())
            .build()
            .map_err(|e| rustls::Error::General(e.to_string()))?
            .verify_server_cert(end_entity, &[], server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.3 only (see enroll_config).
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
