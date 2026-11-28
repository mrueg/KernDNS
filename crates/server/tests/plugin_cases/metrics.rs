//! metrics_test.go: TestMetricsTLS, the `/metrics` endpoint served with a
//! Prometheus web config (`prometheus { tls FILE }`).

use std::sync::Arc;

use kerndns_plugins::http;
use kerndns_plugins::webconfig::Web;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::harness::*;

/// The web configs of CoreDNS's `plugin/metrics/test_data/configs`; their
/// paths are relative to that directory.
const CONFIGS: &[(&str, &str)] = &[
    (
        "certPath_empty.yml",
        "tls_server_config:\n  cert_file: \"\"\n  key_file: \"../server.key\"\n",
    ),
    (
        "certPath_invalid.yml",
        "tls_server_config:\n  cert_file: \"somefile\"\n  key_file: \"../server.key\"\n",
    ),
    ("empty.yml", "\n"),
    (
        "junk.yml",
        "hWkNKCp3fvIx3jKnsaBI\nTuEjdwNS8A2vYdFbiKqr\nay3RiOtykgt4m6m3KOol\nZreGpJRGmpDSVV9cioiF\n",
    ),
    (
        "keyPath_empty.yml",
        "tls_server_config:\n  cert_file: \"../server.crt\"\n  key_file: \"\"\n",
    ),
    (
        "keyPath_invalid.yml",
        "tls_server_config:\n  cert_file: \"../server.cert\"\n  key_file: \"somefile\"\n",
    ),
    (
        "valid_requireanyclientcert.yml",
        "tls_server_config:\n  cert_file: \"../server.crt\"\n  key_file: \"../server.key\"\n  client_auth_type: \"RequireAnyClientCert\"\n",
    ),
    (
        "valid_verifyclientcertifgiven.yml",
        "tls_server_config:\n  cert_file: \"../server.crt\"\n  key_file: \"../server.key\"\n  client_auth_type: \"VerifyClientCertIfGiven\"\n",
    ),
];

/// `createTestCertFiles`: a CA and a server certificate it signs, another
/// CA and a client certificate it signs, and both CAs in one chain file.
fn write_certs(dir: &TempDir) {
    let ca = || {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.distinguished_name.push(rcgen::DnType::OrganizationName, "Test CA");
        let pem = p.self_signed(&key).unwrap().pem();
        (rcgen::Issuer::new(p, key), pem)
    };
    let leaf = |issuer: &rcgen::Issuer<'_, rcgen::KeyPair>| {
        let key = rcgen::KeyPair::generate().unwrap();
        let p = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
        (p.signed_by(&key, issuer).unwrap().pem(), key.serialize_pem())
    };
    let (server_ca, server_ca_pem) = ca();
    let (cert, key) = leaf(&server_ca);
    let (client_ca, client_ca_pem) = ca();
    let (client_cert, client_key) = leaf(&client_ca);
    dir.write("test_data/server.crt", &cert);
    dir.write("test_data/server.key", &key);
    dir.write("test_data/client_selfsigned.crt", &client_cert);
    dir.write("test_data/client_selfsigned.key", &client_key);
    dir.write("test_data/tls-ca-chain.pem", &format!("{server_ca_pem}{client_ca_pem}"));
}

/// `getTLSClient`: trusts the CA chain, presents the client certificate
/// if asked to.
fn tls_client(dir: &TempDir, client_cert: bool) -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let read = |n: &str| std::fs::read(dir.0.join("test_data").join(n)).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&read("tls-ca-chain.pem")) {
        roots.add(c.unwrap()).unwrap();
    }
    let b = rustls::ClientConfig::builder().with_root_certificates(roots);
    let cfg = if client_cert {
        let certs = CertificateDer::pem_slice_iter(&read("client_selfsigned.crt"))
            .map(Result::unwrap)
            .collect();
        let key = PrivateKeyDer::from_pem_slice(&read("client_selfsigned.key")).unwrap();
        b.with_client_auth_cert(certs, key).unwrap()
    } else {
        b.with_no_client_auth()
    };
    Arc::new(cfg)
}

/// GET /metrics; the status code, or the error.
async fn get(addr: std::net::SocketAddr, tls: Option<Arc<rustls::ClientConfig>>) -> Result<u16, String> {
    let req = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let s = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    match tls {
        None => {
            let mut s = s;
            s.write_all(req).await.map_err(|e| e.to_string())?;
            let _ = s.read_to_end(&mut out).await;
        }
        Some(cfg) => {
            let name = ServerName::try_from("localhost").unwrap();
            let mut s = tokio_rustls::TlsConnector::from(cfg)
                .connect(name, s)
                .await
                .map_err(|e| e.to_string())?;
            s.write_all(req).await.map_err(|e| e.to_string())?;
            if let Err(e) = s.read_to_end(&mut out).await
                && out.is_empty()
            {
                return Err(e.to_string());
            }
        }
    }
    let text = String::from_utf8_lossy(&out);
    let code = text.split(' ').nth(1).and_then(|c| c.parse().ok());
    code.ok_or_else(|| format!("no HTTP response: {text:?}"))
}

pub async fn metrics(r: &mut Run) {
    let id = "TestMetricsTLS/tests";
    let dir = TempDir::new();
    std::fs::create_dir_all(dir.0.join("test_data/configs")).unwrap();
    for (name, yaml) in CONFIGS {
        dir.write(&format!("test_data/configs/{name}"), yaml);
    }
    write_certs(&dir);
    for (row, v) in r.rows(id) {
        let path = v["tlsConfigPath"].as_str().unwrap_or("");
        let use_tls = v["UseTLSClient"].as_bool().unwrap_or(false);
        let client_cert = v["clientCertificate"].as_bool().unwrap_or(false);
        let want_startup_err = v["expectStartupError"].as_bool().unwrap_or(false);
        let want_request_err = v["expectRequestError"].as_bool().unwrap_or(false);
        // met.OnStartup()
        let web = if path.is_empty() {
            Ok(None)
        } else {
            Web::new(&dir.0.join(path).to_string_lossy()).map(|w| Some(Arc::new(w)))
        };
        let res = match (web, want_startup_err) {
            (Err(_), true) => Ok(()),
            (Ok(_), true) => Err("Expected error but got none".to_string()),
            (Err(e), false) => Err(format!("Failed to start metrics handler: {e}")),
            (Ok(web), false) => {
                let route: http::Route = Arc::new(|_, _| http::text(200, "ok"));
                let ep = http::serve_web("127.0.0.1:0", route, web).unwrap();
                let client = use_tls.then(|| tls_client(&dir, client_cert));
                let got = get(ep.addr, client).await;
                let addr = ep.addr;
                tokio::task::spawn_blocking(move || ep.stop()).await.unwrap();
                match (got, want_request_err) {
                    (Ok(200), false) => Ok(()),
                    // a request error, or HTTP to the HTTPS server
                    (Err(_), true) | (Ok(400), true) => Ok(()),
                    (got, _) => Err(format!("{addr}: want request error {want_request_err}, got {got:?}")),
                }
            }
        };
        r.check(id, &row, res);
    }
}
