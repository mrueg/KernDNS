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

/// A server config from `tls CERT KEY [CA]`, like `NewTLSConfig`. Client
/// certificates are checked against CA (or the system roots); rustls only
/// accepts verified client certificates, so `request` behaves like
/// `verify_if_given` and `require` like `require_and_verify`.
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
    let builder = match auth {
        ClientAuth::NoCert => builder.with_no_client_auth(),
        _ => {
            let roots = Arc::new(roots(ca)?);
            let v = rustls::server::WebPkiClientVerifier::builder(roots);
            let v = if matches!(auth, ClientAuth::Request | ClientAuth::VerifyIfGiven) {
                v.allow_unauthenticated()
            } else {
                v
            };
            builder.with_client_cert_verifier(v.build().map_err(|e| format!("client verifier: {e}"))?)
        }
    };
    let cfg = builder
        .with_single_cert(certs, key)
        .map_err(|e| format!("could not load TLS cert: {e}"))?;
    Ok(Arc::new(cfg))
}
