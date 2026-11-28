//! TLS configuration from Corefile arguments, like CoreDNS's
//! `pkg/tls.NewTLSConfigFromArgs`.
//!
//! Client side (`forward`'s `tls` option):
//! - no arguments: system roots
//! - `CA`: trust only this CA
//! - `CERT KEY`: system roots, present a client certificate
//! - `CERT KEY CA`: both

use std::sync::{Arc, Once};

use rustls::ClientConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

static PROVIDER: Once = Once::new();

/// Install ring as the process-wide rustls crypto provider (once).
pub fn install_provider() {
    PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Vec<_> = CertificateDer::pem_file_iter(path)
        .map_err(|e| format!("could not load TLS cert: open {path}: {e}"))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("could not load TLS cert {path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("could not load TLS cert: no certificates in {path}"));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| format!("could not load TLS key {path}: {e}"))
}

fn roots(ca: Option<&str>) -> Result<rustls::RootCertStore, String> {
    let mut store = rustls::RootCertStore::empty();
    match ca {
        Some(path) => {
            for c in load_certs(path)? {
                store.add(c).map_err(|e| format!("bad CA certificate in {path}: {e}"))?;
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            for c in native.certs {
                let _ = store.add(c);
            }
        }
    }
    Ok(store)
}

/// A client config from 0–3 `tls` arguments.
pub fn client_config(args: &[String]) -> Result<Arc<ClientConfig>, String> {
    install_provider();
    let (cert_key, ca) = match args {
        [] => (None, None),
        [ca] => (None, Some(ca.as_str())),
        [cert, key] => (Some((cert, key)), None),
        [cert, key, ca] => (Some((cert, key)), Some(ca.as_str())),
        _ => return Err("maximum of three arguments allowed for TLS config".into()),
    };
    let builder = ClientConfig::builder().with_root_certificates(roots(ca)?);
    let cfg = match cert_key {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => builder
            .with_client_auth_cert(load_certs(cert)?, load_key(key)?)
            .map_err(|e| format!("bad client certificate: {e}"))?,
    };
    Ok(Arc::new(cfg))
}

/// Client certificate policy of the `tls` plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    NoCert,
    Request,
    Require,
    VerifyIfGiven,
    RequireAndVerify,
}

/// A server config from `tls CERT KEY [CA]`, like `NewTLSConfig`. With
/// `verify_if_given` and `require_and_verify` client certificates are
/// checked against CA (or the system roots); `request` and `require` ask
/// for any certificate without verifying its chain (Go's
/// `RequestClientCert` and `RequireAnyClientCert`), only the handshake
/// signature that proves the client holds its key.
pub fn server_config(
    cert: &str,
    key: &str,
    ca: Option<&str>,
    auth: ClientAuth,
) -> Result<Arc<rustls::ServerConfig>, String> {
    install_provider();
    let certs = load_certs(cert)?;
    let key = load_key(key)?;
    let builder = rustls::ServerConfig::builder();
    let builder = match client_verifier(ca, auth)? {
        None => builder.with_no_client_auth(),
        Some(v) => builder.with_client_cert_verifier(v),
    };
    let cfg = builder
        .with_single_cert(certs, key)
        .map_err(|e| format!("could not load TLS cert: {e}"))?;
    Ok(Arc::new(cfg))
}

/// The client certificate verifier for `auth` (`None`: no client auth).
fn client_verifier(
    ca: Option<&str>,
    auth: ClientAuth,
) -> Result<Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>, String> {
    if auth == ClientAuth::NoCert {
        return Ok(None);
    }
    // the CA is still loaded (and must be valid) for `request` and
    // `require`, as in Go
    client_verifier_with_roots(Some(roots(ca)?), auth)
}

/// The client certificate verifier for `auth`, verifying against `roots`
/// (`None`: the system roots, Go's nil `ClientCAs`).
pub fn client_verifier_with_roots(
    roots_store: Option<rustls::RootCertStore>,
    auth: ClientAuth,
) -> Result<Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>, String> {
    Ok(Some(match auth {
        ClientAuth::NoCert => return Ok(None),
        ClientAuth::Request | ClientAuth::Require => Arc::new(AnyClientCert {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            mandatory: auth == ClientAuth::Require,
        }),
        ClientAuth::VerifyIfGiven | ClientAuth::RequireAndVerify => {
            let roots = Arc::new(match roots_store {
                Some(r) => r,
                None => roots(None)?,
            });
            let v = rustls::server::WebPkiClientVerifier::builder(roots);
            let v = if auth == ClientAuth::VerifyIfGiven {
                v.allow_unauthenticated()
            } else {
                v
            };
            v.build().map_err(|e| format!("client verifier: {e}"))?
        }
    }))
}

/// Accepts any client certificate (`client_auth request|require`).
#[derive(Debug)]
struct AnyClientCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
    mandatory: bool,
}

impl rustls::server::danger::ClientCertVerifier for AnyClientCert {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Writes TLS secrets in the NSS key log format to a file (`tls { keylog
/// FILE }`, Go's `tls.Config.KeyLogWriter`).
pub struct KeyLogFile(std::sync::Mutex<std::fs::File>);

impl std::fmt::Debug for KeyLogFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyLogFile")
    }
}

impl KeyLogFile {
    /// Open `path` for appending (created with mode 0600), like CoreDNS.
    pub fn open(path: &std::path::Path) -> std::io::Result<KeyLogFile> {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)?;
        Ok(KeyLogFile(std::sync::Mutex::new(f)))
    }
}

impl rustls::KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        use std::io::Write;
        // Go's crypto/tls doesn't write the exporter secret
        if label == "EXPORTER_SECRET" {
            return;
        }
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let line = format!("{label} {} {}\n", hex(client_random), hex(secret));
        if let Ok(mut f) = self.0.lock() {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

/// A client config that accepts any server certificate (`skipverify`,
/// Go's `InsecureSkipVerify`).
pub fn insecure_client_config() -> Arc<ClientConfig> {
    use rustls::DigitallySignedStruct;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls_pki_types::{ServerName, UnixTime};

    #[derive(Debug)]
    struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    install_provider();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    Arc::new(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/coredns/plugin/tls");

    /// `request` and `require` accept a client certificate without
    /// verifying it (Go's `RequestClientCert`, `RequireAnyClientCert`);
    /// the verifying modes check it against the CA.
    #[test]
    fn client_auth_modes() {
        install_provider();
        let ca = format!("{DIR}/test_ca.pem");
        assert!(client_verifier(Some(&ca), ClientAuth::NoCert).unwrap().is_none());
        for (auth, mandatory, accepts_any) in [
            (ClientAuth::Request, false, true),
            (ClientAuth::Require, true, true),
            (ClientAuth::VerifyIfGiven, false, false),
            (ClientAuth::RequireAndVerify, true, false),
        ] {
            let v = client_verifier(Some(&ca), auth).unwrap().unwrap();
            assert!(v.offer_client_auth(), "{auth:?}");
            assert_eq!(v.client_auth_mandatory(), mandatory, "{auth:?}");
            let bogus = CertificateDer::from(b"not a certificate".to_vec());
            let res = v.verify_client_cert(&bogus, &[], rustls_pki_types::UnixTime::now());
            assert_eq!(res.is_ok(), accepts_any, "{auth:?}");
        }
        assert!(client_verifier(Some("/nonexistent/ca.pem"), ClientAuth::Request).is_err());
    }
}
