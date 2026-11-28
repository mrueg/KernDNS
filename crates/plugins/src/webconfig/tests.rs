use std::sync::Arc;

use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::*;
use crate::http;
use crate::testutil::TempDir;

/// Certificates for one test: a server CA and a server certificate for
/// 127.0.0.1, and a client CA with two client certificates.
struct Pki {
    dir: TempDir,
    server_ca: CertificateDer<'static>,
    clients: HashMap<&'static str, (String, String)>,
}

fn issuer(name: &str) -> (rcgen::Issuer<'static, rcgen::KeyPair>, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.distinguished_name.push(rcgen::DnType::CommonName, name);
    let pem = p.self_signed(&key).unwrap().pem();
    (rcgen::Issuer::new(p, key), pem)
}

fn leaf(issuer: &rcgen::Issuer<'static, rcgen::KeyPair>, san: &str) -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let p = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
    (p.signed_by(&key, issuer).unwrap().pem(), key.serialize_pem())
}

impl Pki {
    fn new(tag: &str) -> Pki {
        let dir = TempDir::new(tag);
        let (server_issuer, server_ca_pem) = issuer("server CA");
        let (cert, key) = leaf(&server_issuer, "127.0.0.1");
        dir.write("server.crt", &cert);
        dir.write("server.key", &key);
        let (client_issuer, client_ca_pem) = issuer("client CA");
        dir.write("client_ca.crt", &client_ca_pem);
        let mut clients = HashMap::new();
        clients.insert("allowed", leaf(&client_issuer, "client.example"));
        clients.insert("other", leaf(&client_issuer, "other.example"));
        // signed by a CA nobody trusts
        clients.insert("unknown", leaf(&issuer("rogue CA").0, "client.example"));
        let server_ca = CertificateDer::from_pem_slice(server_ca_pem.as_bytes()).unwrap();
        Pki {
            dir,
            server_ca,
            clients,
        }
    }

    /// Write `web.yml` and return its path.
    fn config(&self, yaml: &str) -> String {
        self.dir.write("web.yml", yaml).to_string_lossy().into_owned()
    }

    fn client(&self, cert: Option<&str>, alpn: &[&str]) -> Arc<ClientConfig> {
        tlsconfig::install_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.server_ca.clone()).unwrap();
        let b = ClientConfig::builder().with_root_certificates(roots);
        let mut c = match cert {
            None => b.with_no_client_auth(),
            Some(name) => {
                let (cert, key) = &self.clients[name];
                let certs = vec![CertificateDer::from_pem_slice(cert.as_bytes()).unwrap()];
                b.with_client_auth_cert(certs, PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap())
                    .unwrap()
            }
        };
        c.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        Arc::new(c)
    }
}

/// Serve "ok" on 127.0.0.1 with the web config at `path`.
fn start(path: &str) -> Result<std::net::SocketAddr, String> {
    let web = Web::new(path)?;
    let route: http::Route = Arc::new(|_, _| http::text(200, "ok"));
    let ep = http::serve_web("127.0.0.1:0", route, Some(Arc::new(web))).unwrap();
    // stopped with the test's runtime
    let addr = ep.addr;
    std::mem::forget(ep);
    Ok(addr)
}

const REQUEST: &str = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n";

/// One request over plain HTTP; the raw response.
async fn get_plain(addr: std::net::SocketAddr, headers: &str) -> String {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("{REQUEST}{headers}\r\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out).await;
    out
}

/// One request over TLS; the raw response, or the TLS error.
async fn get_tls(addr: std::net::SocketAddr, client: Arc<ClientConfig>) -> Result<String, String> {
    let s = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(client)
        .connect(name, s)
        .await
        .map_err(|e| e.to_string())?;
    tls.write_all(format!("{REQUEST}\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    match tls.read_to_end(&mut out).await {
        // a rejected client certificate shows up on the first read in TLS 1.3
        Err(e) if out.is_empty() => Err(e.to_string()),
        _ => Ok(String::from_utf8_lossy(&out).into_owned()),
    }
}

/// The ALPN protocol a TLS client offering `alpn` gets.
async fn alpn(addr: std::net::SocketAddr, client: Arc<ClientConfig>) -> Option<Vec<u8>> {
    let s = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("127.0.0.1").unwrap();
    let tls = tokio_rustls::TlsConnector::from(client).connect(name, s).await.unwrap();
    tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
}

fn status(resp: &str) -> &str {
    resp.lines().next().unwrap_or("")
}

/// exporter-toolkit's `TestYAMLFiles` validation cases (`web.Validate`),
/// with the same error patterns.
#[test]
fn validate_like_the_toolkit() {
    let pki = Pki::new("webcfg-validate");
    let dir = pki.dir.0.display().to_string();
    let user_hash = bcrypt::hash("dolor", 4).unwrap();
    let cases: &[(&str, &str, Option<&str>)] = &[
        ("empty", "", None),
        ("comments only", "# nothing\n", None),
        ("junk", "hWkNKCp3fvIx3jKnsaBI\nTuEjdwNS8A2vYdFbiKqr\n", Some("yaml")),
        (
            "junk key",
            "tls_server_config:\n  cert_file: server.crt\n  junk: x\n",
            Some("yaml"),
        ),
        ("junk top key", "tls_config: {}\n", Some("yaml")),
        (
            "cert_file empty",
            "tls_server_config:\n  cert_file: \"\"\n  key_file: server.key\n",
            Some("missing one of cert or cert_file"),
        ),
        (
            "cert empty",
            "tls_server_config:\n  cert: \"\"\n  key_file: server.key\n",
            Some("missing one of cert or cert_file"),
        ),
        (
            "key_file empty",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: \"\"\n",
            Some("missing one of key or key_file"),
        ),
        (
            "both empty",
            "tls_server_config:\n  client_auth_type: RequireAnyClientCert\n",
            Some("missing one of cert or cert_file"),
        ),
        (
            "cert_file invalid",
            "tls_server_config:\n  cert_file: somefile\n  key_file: server.key\n",
            Some("no such file"),
        ),
        (
            "key_file invalid",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: somefile\n",
            Some("no such file"),
        ),
        (
            "valid",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n",
            None,
        ),
        (
            "CA without policy",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  client_ca_file: client_ca.crt\n",
            Some("client CA's have been configured without a Client Auth Policy"),
        ),
        (
            "CA missing",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: somefile\n",
            Some("no such file"),
        ),
        (
            "bad client auth",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  client_auth_type: Sometimes\n",
            Some("invalid ClientAuth: Sometimes"),
        ),
        (
            "bad password hash",
            "basic_auth_users:\n  alice: $2y$10$short\n",
            Some("hashedSecret too short to be a bcrypted password"),
        ),
        (
            "invented cipher",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  cipher_suites: [TLS_RSA_WITH_RC4_128_SHA, TLS_INVENTED]\n",
            Some("unknown cipher"),
        ),
        (
            "invented curve",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  curve_preferences: [CurveP257]\n",
            Some("unknown curve"),
        ),
        (
            "wrong TLS version",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  min_version: TLS111\n",
            Some("unknown TLS version"),
        ),
        (
            "bad X-Content-Type-Options",
            "http_server_config:\n  headers:\n    X-Content-Type-Options: foo\n",
            Some("invalid value for X-Content-Type-Options"),
        ),
        (
            "bad X-Frame-Options",
            "http_server_config:\n  headers:\n    X-Frame-Options: allow\n",
            Some("invalid value for X-Frame-Options"),
        ),
        (
            "extra header",
            "http_server_config:\n  headers:\n    Content-Type: text/plain\n",
            Some("HTTP header \"Content-Type\" can not be configured"),
        ),
        (
            "good headers",
            "http_server_config:\n  headers:\n    X-Frame-Options: deny\n    Strict-Transport-Security: max-age=31536000\n",
            None,
        ),
        (
            "null sections",
            "tls_server_config:\nhttp_server_config:\nbasic_auth_users:\nrate_limit:\n",
            None,
        ),
        (
            "all ciphers and curves",
            "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  cipher_suites: [TLS_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]\n  curve_preferences: [CurveP256, CurveP384, CurveP521, X25519]\n  prefer_server_cipher_suites: false\n",
            None,
        ),
        ("rate limit", "rate_limit:\n  interval: 1s\n  burst: 2\n", None),
        (
            "bad rate limit interval",
            "rate_limit:\n  interval: soon\n",
            Some("yaml"),
        ),
    ];
    let users = format!("basic_auth_users:\n  alice: {user_hash}\n");
    let missing = format!("{dir}/missing.yml");
    assert!(validate(&missing).unwrap_err().contains("no such file"), "missing file");
    assert_eq!(validate(&pki.config(&users)), Ok(()), "users");
    for (name, yaml, want) in cases {
        let got = validate(&pki.config(yaml));
        match (want, got) {
            (None, Ok(())) => {}
            (Some(w), Err(e)) if e.contains(w) => {}
            (w, g) => panic!("{name}: want {w:?}, got {g:?}"),
        }
    }
}

#[test]
fn bcrypt_cost_errors() {
    let ok = bcrypt::hash("x", 5).unwrap();
    assert_eq!(bcrypt_cost(&ok), Ok(5));
    let e = |h: &str| bcrypt_cost(h).unwrap_err();
    assert!(e("$2y$10$").contains("too short"));
    let pad = "a".repeat(53);
    assert!(e(&format!("x2y$10${pad}")).contains("must start with '$'"));
    assert!(e(&format!("$3y$10${pad}")).contains("version '3' requested is newer"));
    assert!(e(&format!("$2y$03${pad}")).contains("cost 3 is outside allowed inclusive range 4..31"));
}

/// Relative paths are relative to the config file, not the working
/// directory; absolute ones are kept.
#[test]
fn paths_relative_to_the_file() {
    let pki = Pki::new("webcfg-paths");
    let dir = pki.dir.0.display().to_string();
    let c = load(&pki.config("tls_server_config:\n  cert_file: server.crt\n  key_file: /abs/server.key\n")).unwrap();
    assert_eq!(c.tls_server_config.cert_file, format!("{dir}/server.crt"));
    assert_eq!(c.tls_server_config.key_file, "/abs/server.key");
}

/// The check `ServeTLS` makes when HTTP/2 is on.
#[test]
fn http2_needs_an_aes128_gcm_cipher() {
    let pki = Pki::new("webcfg-h2");
    let base = "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  cipher_suites: [TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]\n";
    let e = Web::new(&pki.config(base)).err().unwrap();
    assert!(
        e.starts_with(
            "Failed to start HTTPS metrics server: http2: TLSConfig.CipherSuites is missing an HTTP/2-required"
        ),
        "{e}"
    );
    assert!(Web::new(&pki.config(&format!("{base}http_server_config:\n  http2: false\n"))).is_ok());
    assert!(Web::new(&pki.config(&format!("{base}  min_version: TLS13\n"))).is_ok());
}

#[tokio::test]
async fn https_and_client_certificates() {
    let pki = Pki::new("webcfg-https");
    let tls = "tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n";

    // VerifyClientCertIfGiven: a TLS client without a certificate is fine,
    // plain HTTP gets Go's 400
    let addr = start(&pki.config(&format!("{tls}  client_auth_type: VerifyClientCertIfGiven\n"))).unwrap();
    let resp = get_tls(addr, pki.client(None, &[])).await.unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 200 OK");
    assert!(resp.ends_with("ok"), "{resp}");
    let resp = get_plain(addr, "").await;
    assert_eq!(
        resp,
        "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"
    );

    // RequireAnyClientCert: any certificate, even from an unknown CA
    let addr = start(&pki.config(&format!("{tls}  client_auth_type: RequireAnyClientCert\n"))).unwrap();
    assert!(get_tls(addr, pki.client(None, &[])).await.is_err());
    let resp = get_tls(addr, pki.client(Some("unknown"), &[])).await.unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 200 OK");

    // RequireAndVerifyClientCert with a CA and allowed SANs
    let cfg = format!(
        "{tls}  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: client_ca.crt\n  client_allowed_sans: [client.example]\n"
    );
    let addr = start(&pki.config(&cfg)).unwrap();
    let resp = get_tls(addr, pki.client(Some("allowed"), &[])).await.unwrap();
    assert_eq!(status(&resp), "HTTP/1.1 200 OK");
    assert!(
        get_tls(addr, pki.client(Some("other"), &[])).await.is_err(),
        "SAN not allowed"
    );
    assert!(
        get_tls(addr, pki.client(Some("unknown"), &[])).await.is_err(),
        "unknown CA"
    );
    assert!(get_tls(addr, pki.client(None, &[])).await.is_err(), "no certificate");

    // HTTP/2 is offered unless turned off
    let addr = start(&pki.config(tls)).unwrap();
    assert_eq!(
        alpn(addr, pki.client(None, &["h2", "http/1.1"])).await.as_deref(),
        Some(&b"h2"[..])
    );
    let addr = start(&pki.config(&format!("{tls}http_server_config:\n  http2: false\n"))).unwrap();
    assert_eq!(
        alpn(addr, pki.client(None, &["h2", "http/1.1"])).await.as_deref(),
        Some(&b"http/1.1"[..])
    );
}

/// The certificates are read again for every handshake.
#[tokio::test]
async fn certificates_reload() {
    let pki = Pki::new("webcfg-reload");
    let addr = start(&pki.config("tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n")).unwrap();
    assert!(get_tls(addr, pki.client(None, &[])).await.is_ok());
    // a certificate from another CA: the old client no longer trusts it
    let (other, _) = issuer("another server CA");
    let (cert, key) = leaf(&other, "127.0.0.1");
    pki.dir.write("server.crt", &cert);
    pki.dir.write("server.key", &key);
    assert!(get_tls(addr, pki.client(None, &[])).await.is_err());
}

#[tokio::test]
async fn basic_auth_headers_and_rate_limit() {
    let pki = Pki::new("webcfg-auth");
    let hash = bcrypt::hash("dolor", 4).unwrap();
    let path = pki.config(&format!(
        "basic_auth_users:\n  alice: {hash}\nhttp_server_config:\n  headers:\n    X-Frame-Options: deny\n"
    ));
    // no TLS settings: plain HTTP, with the users and headers
    let addr = start(&path).unwrap();
    let auth = |u: &str, p: &str| {
        format!(
            "Authorization: Basic {}\r\n",
            data_encoding::BASE64.encode(format!("{u}:{p}").as_bytes())
        )
    };
    let resp = get_plain(addr, "").await;
    assert_eq!(status(&resp), "HTTP/1.1 401 Unauthorized");
    let lower = resp.to_ascii_lowercase();
    assert!(lower.contains("www-authenticate: basic\r\n"), "{resp}");
    assert!(lower.contains("x-frame-options: deny\r\n"), "{resp}");
    assert!(resp.ends_with("Unauthorized\n"), "{resp}");
    for (u, p) in [("alice", "wrong"), ("bob", "dolor"), ("alice", "wrong")] {
        assert_eq!(
            status(&get_plain(addr, &auth(u, p)).await),
            "HTTP/1.1 401 Unauthorized",
            "{u}:{p}"
        );
    }
    let resp = get_plain(addr, &auth("alice", "dolor")).await;
    assert_eq!(status(&resp), "HTTP/1.1 200 OK");
    assert!(
        resp.to_ascii_lowercase().contains("x-frame-options: deny\r\n"),
        "{resp}"
    );

    // the file is read for every request: a new user works right away
    let hash2 = bcrypt::hash("amet", 4).unwrap();
    pki.config(&format!("basic_auth_users:\n  alice: {hash}\n  carol: {hash2}\n"));
    assert_eq!(
        status(&get_plain(addr, &auth("carol", "amet")).await),
        "HTTP/1.1 200 OK"
    );
    // and a broken one is a 500
    pki.config("junk: [");
    assert_eq!(
        status(&get_plain(addr, &auth("carol", "amet")).await),
        "HTTP/1.1 500 Internal Server Error"
    );

    // rate_limit: one request per hour, burst 2
    let addr = start(&pki.config("rate_limit:\n  interval: 1h\n  burst: 2\n")).unwrap();
    for want in ["200 OK", "200 OK", "429 Too Many Requests"] {
        assert_eq!(status(&get_plain(addr, "").await), format!("HTTP/1.1 {want}"));
    }
}

#[test]
fn startup_errors() {
    let pki = Pki::new("webcfg-start");
    let e = Web::new(&pki.config("tls_server_config:\n  cert_file: server.crt\n  key_file: nope.key\n"))
        .err()
        .unwrap();
    assert!(e.starts_with("Invalid TLS config: failed to read key_file ("), "{e}");
    assert!(e.ends_with("nope.key: no such file or directory"), "{e}");
    let e = Web::new(
        &pki.config("tls_server_config:\n  cert_file: server.crt\n  key_file: server.key\n  max_version: TLS11\n"),
    )
    .err()
    .unwrap();
    assert!(e.contains("max_version below TLS12"), "{e}");
}

#[test]
fn limiter_refills() {
    let mut l = Limiter::new(Duration::from_millis(20), 1);
    assert!(l.allow());
    assert!(!l.allow());
    std::thread::sleep(Duration::from_millis(30));
    assert!(l.allow());
    let mut none = Limiter::new(Duration::from_secs(1), 0);
    assert!(!none.allow());
}
