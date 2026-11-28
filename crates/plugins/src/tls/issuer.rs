//! Obtaining and renewing ACME certificates with `instant-acme`, and
//! keeping them in certmagic's storage layout:
//!
//! ```text
//! <storage>/acme/<issuer>/users/<email>/<user>.key|.json    account
//! <storage>/certificates/<issuer>/<name>/<name>.crt|.key|.json
//! ```
//!
//! `<issuer>` is the CA URL's host and path (`acme-v02.api.letsencrypt.org-directory`),
//! names are made file-safe like certmagic's `StorageKeys.Safe`.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::Name as HostName;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, HttpClient, Identifier, Key, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::{Name, RData, RecordType};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

use super::acme::{AcmeOptions, Entry, Managed, Solver};

/// How often to look at certificates that are not due yet (certmagic's
/// `RenewCheckInterval`).
const RENEW_CHECK: i64 = 10 * 60;

/// Waits between failed attempts, then every 6 hours (close to
/// certmagic's `retryIntervals`).
const RETRY: &[i64] = &[
    60, 120, 120, 300, 600, 600, 600, 1200, 1200, 1200, 1200, 1800, 1800, 1800, 1800, 1800, 1800, 3600, 3600, 3600,
    7200, 7200, 7200, 21600,
];

fn q(s: &str) -> String {
    format!("{s:?}")
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Storage

/// certmagic's `StorageKeys.Safe`.
pub fn safe_key(s: &str) -> String {
    let s = s.trim().to_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut rest = s.as_str();
    while let Some(c) = rest.chars().next() {
        let (repl, n): (&str, usize) = match c {
            ' ' => ("_", 1),
            '+' => ("_plus_", 1),
            '*' => ("wildcard_", 1),
            ':' => ("-", 1),
            '.' if rest.starts_with("..") => ("", 2),
            _ => {
                out.push(c);
                rest = &rest[c.len_utf8()..];
                continue;
            }
        };
        out.push_str(repl);
        rest = &rest[n..];
    }
    out.retain(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '@' | '.' | '-'));
    out
}

/// certmagic's `ACMEIssuer.issuerKey`: the CA URL's host plus its path
/// with slashes turned into hyphens.
pub fn issuer_key(ca: &str) -> String {
    let Ok(uri) = ca.parse::<http::Uri>() else {
        return ca.to_string();
    };
    let mut key = uri
        .authority()
        .map(|a| a.as_str().rsplit('@').next().unwrap_or_default().to_string())
        .unwrap_or_default();
    let path = uri.path().replace(['/', '\\'], "-");
    let path = path.trim_matches('-');
    if !path.is_empty() {
        key.push('-');
        key.push_str(path);
    }
    key
}

struct CertPaths {
    crt: PathBuf,
    key: PathBuf,
    meta: PathBuf,
}

fn cert_paths(o: &AcmeOptions, domain: &str) -> CertPaths {
    let name = safe_key(domain);
    let dir = o
        .storage
        .join("certificates")
        .join(safe_key(&issuer_key(&o.ca)))
        .join(&name);
    CertPaths {
        crt: dir.join(format!("{name}.crt")),
        key: dir.join(format!("{name}.key")),
        meta: dir.join(format!("{name}.json")),
    }
}

/// The account's key and registration files.
fn account_paths(o: &AcmeOptions) -> (PathBuf, PathBuf) {
    let email = if o.email.is_empty() {
        "default".to_string()
    } else {
        o.email.to_lowercase()
    };
    // emailUsername: the part before '@'
    let user = match email.find('@') {
        None => email.as_str(),
        Some(0) => &email[1..],
        Some(i) => &email[..i],
    };
    let user = if user.is_empty() { "default" } else { user };
    let dir = o
        .storage
        .join("acme")
        .join(safe_key(&issuer_key(&o.ca)))
        .join("users")
        .join(safe_key(&email));
    let user = safe_key(user);
    (dir.join(format!("{user}.key")), dir.join(format!("{user}.json")))
}

/// Write `data` atomically with mode 0600 in directories with mode 0700,
/// like certmagic's `FileStorage`.
fn write_file(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        std::process::id()
    ));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// A certificate chain and key in PEM, as stored and as issued.
pub fn managed_from_pem(chain: &[u8], key: &[u8]) -> Result<Managed, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("bad certificate PEM: {e}"))?;
    let leaf = certs.first().ok_or("no certificates in PEM data")?;
    let (not_before, not_after) = validity(leaf).ok_or("cannot read the certificate's validity")?;
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| format!("bad private key PEM: {e}"))?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| format!("bad private key: {e}"))?;
    Ok(Managed {
        key: Arc::new(CertifiedKey::new(certs, signer)),
        not_before,
        not_after,
    })
}

/// Load the stored certificates of `e` into its store, like certmagic's
/// `CacheManagedCertificate`; missing ones are not an error.
pub fn load_managed(e: &Entry) -> Result<(), String> {
    for d in &e.options.domains {
        let p = cert_paths(&e.options, d);
        let (chain, key) = match (std::fs::read(&p.crt), std::fs::read(&p.key)) {
            (Ok(c), Ok(k)) => (c, k),
            (Err(err), _) | (_, Err(err)) if err.kind() == io::ErrorKind::NotFound => continue,
            (Err(err), _) | (_, Err(err)) => return Err(format!("{d}: {err}")),
        };
        let m = managed_from_pem(&chain, &key).map_err(|err| format!("{d}: {err}"))?;
        kerndns_core::info!(
            plugin = "tls",
            "loaded certificate for {} from {}",
            q(d),
            p.crt.display()
        );
        e.store.set(d, m);
    }
    Ok(())
}

/// The PEM certificates of a `ca_root` file (`loadACMETrustedRoots`).
pub fn load_roots(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let shown = q(&path.display().to_string());
    let pem = std::fs::read(path).map_err(|e| format!("reading ACME CA root {shown}: {e}"))?;
    let certs: Vec<_> = CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok).collect();
    if certs.is_empty() {
        return Err(format!("ACME CA root {shown} contains no certificates"));
    }
    Ok(certs)
}

// ---------------------------------------------------------------------------
// HTTP client for the ACME server

/// Verifies the ACME server against the system roots plus `ca_root`. A
/// server certificate that is itself in `ca_root` is accepted as is (for
/// its name), as Go does; webpki would refuse a self-signed CA certificate
/// as the server's own (`CaUsedAsEndEntity`).
#[derive(Debug)]
struct Verifier {
    inner: Arc<WebPkiServerVerifier>,
    pinned: Vec<CertificateDer<'static>>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
        {
            Ok(v) => Ok(v),
            Err(e) if self.pinned.iter().any(|p| p.as_ref() == end_entity.as_ref()) => {
                let cert = webpki::EndEntityCert::try_from(end_entity).map_err(|_| e.clone())?;
                cert.verify_is_valid_for_subject_name(server_name).map_err(|_| e)?;
                Ok(ServerCertVerified::assertion())
            }
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Resolves the ACME server's name through the `resolver` option (A and
/// AAAA over UDP), like Go's resolver with a custom dial address.
#[derive(Clone)]
struct DnsResolver(String);

impl tower_service::Service<HostName> for DnsResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: HostName) -> Self::Future {
        let server = self.0.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let ips = resolve(&server, &host).await?;
            Ok(ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 0))
                .collect::<Vec<_>>()
                .into_iter())
        })
    }
}

async fn resolve(server: &str, host: &str) -> io::Result<Vec<IpAddr>> {
    let server = tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("no address for resolver {server}")))?;
    let name = Name::from_ascii(format!("{}.", host.trim_end_matches('.'))).map_err(io::Error::other)?;
    let mut ips = Vec::new();
    for qtype in [RecordType::A, RecordType::AAAA] {
        let id = kerndns_core::random::rand_id();
        let mut m = Message::new(id, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(name.clone(), qtype));
        let wire = m.to_vec().map_err(io::Error::other)?;
        let bind: SocketAddr = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }
            .parse()
            .expect("valid");
        let sock = tokio::net::UdpSocket::bind(bind).await?;
        sock.connect(server).await?;
        sock.send(&wire).await?;
        let mut buf = vec![0u8; 65535];
        let reply = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let n = sock.recv(&mut buf).await?;
                if let Ok(r) = Message::from_vec(&buf[..n])
                    && r.metadata.id == id
                {
                    return Ok::<_, io::Error>(r);
                }
            }
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("lookup {host} on {server}: timeout")))??;
        for rr in &reply.answers {
            match &rr.data {
                RData::A(a) => ips.push(IpAddr::V4(a.0)),
                RData::AAAA(a) => ips.push(IpAddr::V6(a.0)),
                _ => {}
            }
        }
    }
    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("lookup {host} on {server}: no such host"),
        ));
    }
    Ok(ips)
}

fn http_client(o: &AcmeOptions) -> Result<Box<dyn HttpClient>, String> {
    crate::tlsconfig::install_provider();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    let pinned = match &o.ca_root {
        Some(p) => load_roots(p)?,
        None => Vec::new(),
    };
    for c in &pinned {
        let _ = roots.add(c.clone());
    }
    let inner = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("ACME TLS verifier: {e}"))?;
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier { inner, pinned }))
        .with_no_client_auth();
    let builder = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .enable_http2();
    let exec = TokioExecutor::new();
    Ok(match &o.resolver {
        Some(r) => {
            let mut http = HttpConnector::new_with_resolver(DnsResolver(r.clone()));
            http.enforce_http(false);
            Box::new(Client::builder(exec).build(builder.wrap_connector(http)))
        }
        None => {
            let mut http = HttpConnector::new();
            http.enforce_http(false);
            Box::new(Client::builder(exec).build(builder.wrap_connector(http)))
        }
    })
}

// ---------------------------------------------------------------------------
// Issuing

struct Issuer {
    entry: Arc<Entry>,
    solver: Arc<Solver>,
    account: Option<Account>,
}

/// PKCS#8 DER from a PEM private key; SEC1 P-256 keys (what certmagic
/// writes for ECDSA accounts) are wrapped.
fn account_key(pem: &[u8]) -> Result<PrivatePkcs8KeyDer<'static>, String> {
    match PrivateKeyDer::from_pem_slice(pem).map_err(|e| format!("bad account key: {e}"))? {
        PrivateKeyDer::Pkcs8(k) => Ok(k),
        PrivateKeyDer::Sec1(k) => Ok(PrivatePkcs8KeyDer::from(sec1_to_pkcs8(k.secret_sec1_der()))),
        _ => Err("unsupported account key type (want ECDSA P-256)".into()),
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    use data_encoding::BASE64;
    let b64 = BASE64.encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

impl Issuer {
    async fn account(&mut self) -> Result<Account, String> {
        if let Some(a) = &self.account {
            return Ok(a.clone());
        }
        let o = &self.entry.options;
        let (key_path, json_path) = account_paths(o);
        let http = http_client(o)?;
        let account = match std::fs::read(&key_path) {
            Ok(pem_data) => {
                let der = account_key(&pem_data)?;
                let location = std::fs::read(&json_path)
                    .ok()
                    .and_then(|j| serde_json::from_slice::<serde_json::Value>(&j).ok())
                    .and_then(|v| v.get("location")?.as_str().map(str::to_string))
                    .filter(|l| !l.is_empty());
                match location {
                    Some(id) => Account::builder_with_http(http)
                        .from_parts(id, der, o.ca.clone())
                        .await
                        .map_err(|e| format!("loading ACME account: {e}"))?,
                    None => {
                        let key = Key::from_pkcs8_der(der.clone_key()).map_err(|e| format!("bad account key: {e}"))?;
                        let (account, _) = Account::builder_with_http(http)
                            .create_from_key((key, PrivateKeyDer::Pkcs8(der)), o.ca.clone())
                            .await
                            .map_err(|e| format!("looking up ACME account: {e}"))?;
                        self.save_account(&json_path, &account)?;
                        account
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mailto = format!("mailto:{}", o.email);
                let contact: Vec<&str> = if o.email.is_empty() {
                    vec![]
                } else {
                    vec![mailto.as_str()]
                };
                let (account, creds) = Account::builder_with_http(http)
                    .create(
                        &NewAccount {
                            contact: &contact,
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        o.ca.clone(),
                        None,
                    )
                    .await
                    .map_err(|e| format!("registering ACME account: {e}"))?;
                write_file(
                    &key_path,
                    pem("PRIVATE KEY", creds.private_key().secret_pkcs8_der()).as_bytes(),
                )
                .map_err(|e| format!("saving ACME account key: {e}"))?;
                self.save_account(&json_path, &account)?;
                kerndns_core::info!(plugin = "tls", "registered ACME account {} with {}", account.id(), o.ca);
                account
            }
            Err(e) => return Err(format!("reading ACME account key: {e}")),
        };
        self.account = Some(account.clone());
        Ok(account)
    }

    /// The registration in acmez's `acme.Account` JSON, as certmagic writes it.
    fn save_account(&self, path: &Path, account: &Account) -> Result<(), String> {
        let o = &self.entry.options;
        let mut v = serde_json::json!({
            "status": "valid",
            "termsOfServiceAgreed": true,
            "location": account.id(),
        });
        if !o.email.is_empty() {
            v["contact"] = serde_json::json!([format!("mailto:{}", o.email)]);
        }
        write_file(path, v.to_string().as_bytes()).map_err(|e| format!("saving ACME account: {e}"))
    }

    /// Run one order for `domain` and store the certificate.
    async fn obtain(&mut self, domain: &str) -> Result<Managed, String> {
        let account = self.account().await?;
        let mut presented: Vec<(String, String)> = Vec::new();
        let res = self.order(&account, domain, &mut presented).await;
        for (name, value) in &presented {
            self.solver.cleanup(name, value);
        }
        let (chain, key) = res?;
        let o = &self.entry.options;
        let p = cert_paths(o, domain);
        let meta = serde_json::json!({ "sans": [domain], "issuer_data": { "ca": o.ca } });
        write_file(&p.crt, chain.as_bytes())
            .and_then(|_| write_file(&p.key, key.as_bytes()))
            .and_then(|_| write_file(&p.meta, meta.to_string().as_bytes()))
            .map_err(|e| format!("saving certificate: {e}"))?;
        managed_from_pem(chain.as_bytes(), key.as_bytes())
    }

    async fn order(
        &self,
        account: &Account,
        domain: &str,
        presented: &mut Vec<(String, String)>,
    ) -> Result<(String, String), String> {
        let ids = [Identifier::Dns(domain.to_string())];
        let mut order = account
            .new_order(&NewOrder::new(&ids))
            .await
            .map_err(|e| format!("creating order: {e}"))?;
        let mut authzs = order.authorizations();
        while let Some(a) = authzs.next().await {
            let mut a = a.map_err(|e| format!("fetching authorization: {e}"))?;
            match a.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                s => return Err(format!("authorization is {s:?}")),
            }
            let mut ch = a
                .challenge(ChallengeType::Dns01)
                .ok_or("the ACME server offered no DNS-01 challenge")?;
            let base = match ch.identifier().identifier {
                Identifier::Dns(n) => n.trim_start_matches("*.").to_string(),
                other => return Err(format!("unexpected identifier {other:?}")),
            };
            let name = format!("_acme-challenge.{base}.");
            let value = ch.key_authorization().dns_value();
            self.solver.present(&name, &value);
            presented.push((name, value));
            ch.set_ready().await.map_err(|e| format!("answering challenge: {e}"))?;
        }
        let retry = RetryPolicy::new()
            .initial_delay(Duration::from_millis(250))
            .backoff(1.5)
            .timeout(Duration::from_secs(120));
        let status = order
            .poll_ready(&retry)
            .await
            .map_err(|e| format!("waiting for the order: {e}"))?;
        if status != OrderStatus::Ready {
            let detail = order
                .state()
                .error
                .as_ref()
                .map(|p| format!(": {p}"))
                .unwrap_or_default();
            return Err(format!("order is {status:?}{detail}"));
        }
        let key = order.finalize().await.map_err(|e| format!("finalizing order: {e}"))?;
        let chain = order
            .poll_certificate(&retry)
            .await
            .map_err(|e| format!("downloading certificate: {e}"))?;
        Ok((chain, key))
    }
}

/// Obtain missing certificates and renew due ones until aborted
/// (certmagic's `ManageAsync` and renewal loop).
pub async fn manage(entry: Arc<Entry>, solver: Arc<Solver>) {
    let mut iss = Issuer {
        entry: entry.clone(),
        solver,
        account: None,
    };
    // failed attempts and the next try, by domain
    let mut failures: HashMap<String, (usize, i64)> = HashMap::new();
    loop {
        let mut wake = now() + RENEW_CHECK;
        for d in &entry.options.domains {
            let due = entry.store.get(d).map(|m| m.renew_at()).unwrap_or(i64::MIN);
            let retry_at = failures.get(d).map(|f| f.1).unwrap_or(i64::MIN);
            let when = due.max(retry_at);
            if when > now() {
                wake = wake.min(when);
                continue;
            }
            let renewing = entry.store.get(d).is_some();
            kerndns_core::info!(
                plugin = "tls",
                "{} certificate for {}",
                if renewing { "renewing" } else { "obtaining" },
                q(d)
            );
            match iss.obtain(d).await {
                Ok(m) => {
                    kerndns_core::info!(plugin = "tls", "certificate obtained successfully for {}", q(d));
                    wake = wake.min(m.renew_at());
                    entry.store.set(d, m);
                    failures.remove(d);
                }
                Err(e) => {
                    let f = failures.entry(d.clone()).or_insert((0, 0));
                    let delay = RETRY[f.0.min(RETRY.len() - 1)];
                    f.0 += 1;
                    f.1 = now() + delay;
                    wake = wake.min(f.1);
                    // the account may be what failed
                    iss.account = None;
                    kerndns_core::error!(
                        plugin = "tls",
                        "could not get certificate for {} (attempt {}), retrying in {delay}s: {e}",
                        q(d),
                        f.0
                    );
                }
            }
        }
        let secs = (wake - now()).max(1) as u64;
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
}

// ---------------------------------------------------------------------------
// DER helpers

/// One DER TLV: (tag, contents, rest).
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        (len, &rest[n..])
    };
    if rest.len() < len {
        return None;
    }
    Some((tag, &rest[..len], &rest[len..]))
}

/// Days since 1970-01-01 of a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// UTCTime (0x17) or GeneralizedTime (0x18) in Unix seconds.
fn der_time(tag: u8, v: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(v).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if s.len() == 12 => {
            let yy: i64 = s[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &s[2..])
        }
        0x18 if s.len() == 14 => (s[..4].parse().ok()?, &s[4..]),
        _ => return None,
    };
    let n = |i: usize| rest.get(i..i + 2)?.parse::<i64>().ok();
    let days = days_from_civil(year, n(0)?, n(2)?);
    Some(days * 86400 + n(4)? * 3600 + n(6)? * 60 + n(8)?)
}

/// notBefore and notAfter of an X.509 certificate.
pub fn validity(cert: &[u8]) -> Option<(i64, i64)> {
    let (_, certificate, _) = tlv(cert)?;
    let (_, tbs, _) = tlv(certificate)?;
    let mut rest = tbs;
    // [0] version (optional)
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.2;
    }
    rest = tlv(rest)?.2; // serialNumber
    rest = tlv(rest)?.2; // signature
    rest = tlv(rest)?.2; // issuer
    let (_, validity, _) = tlv(rest)?;
    let (t1, v1, rest) = tlv(validity)?;
    let (t2, v2, _) = tlv(rest)?;
    Some((der_time(t1, v1)?, der_time(t2, v2)?))
}

fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = contents.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len.to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(contents);
    out
}

/// Wrap a SEC1 `ECPrivateKey` for P-256 in PKCS#8 `PrivateKeyInfo`.
fn sec1_to_pkcs8(sec1: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier { id-ecPublicKey, prime256v1 }
    const ALG: &[u8] = &[
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x03, 0x01, 0x07,
    ];
    let mut body = vec![0x02, 0x01, 0x00];
    body.extend_from_slice(ALG);
    body.extend(der(0x04, sec1));
    der(0x30, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/coredns/plugin/tls");

    #[test]
    fn storage_layout() {
        assert_eq!(safe_key("*.Example.org"), "wildcard_.example.org");
        assert_eq!(safe_key("a b+c:d/../e"), "a_b_plus_c-de");
        assert_eq!(
            issuer_key("https://acme-v02.api.letsencrypt.org/directory"),
            "acme-v02.api.letsencrypt.org-directory"
        );
        assert_eq!(issuer_key("https://127.0.0.1:14000/dir"), "127.0.0.1:14000-dir");
        assert_eq!(issuer_key("https://ca.example"), "ca.example");
        let o = AcmeOptions {
            domains: vec!["dns.example".into()],
            email: "Hostmaster@Example.org".into(),
            ca: "https://127.0.0.1:14000/dir".into(),
            storage: "/s".into(),
            ..Default::default()
        };
        let p = cert_paths(&o, "*.dns.example");
        assert_eq!(
            p.crt,
            Path::new("/s/certificates/127.0.0.1-14000-dir/wildcard_.dns.example/wildcard_.dns.example.crt")
        );
        assert_eq!(p.meta.extension().unwrap(), "json");
        let (key, json) = account_paths(&o);
        assert_eq!(
            key,
            Path::new("/s/acme/127.0.0.1-14000-dir/users/hostmaster@example.org/hostmaster.key")
        );
        assert_eq!(json.file_name().unwrap(), "hostmaster.json");
        let o = AcmeOptions {
            email: String::new(),
            ..o
        };
        assert_eq!(
            account_paths(&o).0,
            Path::new("/s/acme/127.0.0.1-14000-dir/users/default/default.key")
        );
    }

    #[test]
    fn certificate_validity() {
        let chain = std::fs::read(format!("{DIR}/test_cert.pem")).unwrap();
        let key = std::fs::read(format!("{DIR}/test_key.pem")).unwrap();
        let m = managed_from_pem(&chain, &key).unwrap();
        assert!(m.not_before < m.not_after);
        assert_eq!(m.renew_at(), m.not_after - (m.not_after - m.not_before) / 3);
        assert_eq!(der_time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(der_time(0x17, b"491231235959Z"), Some(2524607999));
        assert_eq!(der_time(0x18, b"20000301000000Z"), Some(951868800));
        assert_eq!(der_time(0x18, b"2000030100000Z"), None);
    }

    #[test]
    fn issued_certificate_round_trip() {
        // a P-256 certificate like the ones ACME servers issue
        let kp = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["dns.example".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2026, 1, 31);
        let cert = params.self_signed(&kp).unwrap();
        let m = managed_from_pem(cert.pem().as_bytes(), kp.serialize_pem().as_bytes()).unwrap();
        let jan1 = days_from_civil(2026, 1, 1) * 86400;
        assert_eq!(m.not_before, jan1);
        assert_eq!(m.not_after, jan1 + 30 * 86400);
        assert_eq!(m.renew_at(), jan1 + 20 * 86400);
    }

    #[test]
    fn sec1_account_keys() {
        let kp = rcgen::KeyPair::generate().unwrap();
        let pkcs8 = kp.serialize_der();
        // pull the ECPrivateKey out of PKCS#8 and wrap it again
        let (_, info, _) = tlv(&pkcs8).unwrap();
        let rest = tlv(info).unwrap().2; // version
        let rest = tlv(rest).unwrap().2; // algorithm
        let (tag, sec1, _) = tlv(rest).unwrap();
        assert_eq!(tag, 0x04);
        let pem_data = pem("EC PRIVATE KEY", sec1);
        let der = account_key(pem_data.as_bytes()).unwrap();
        Key::from_pkcs8_der(der).unwrap();
        let der = account_key(pem("PRIVATE KEY", &pkcs8).as_bytes()).unwrap();
        assert_eq!(der.secret_pkcs8_der(), &pkcs8[..]);
    }

    #[test]
    fn ca_roots() {
        assert_eq!(load_roots(Path::new(&format!("{DIR}/test_ca.pem"))).unwrap().len(), 1);
        let e = load_roots(Path::new(&format!("{DIR}/test_key.pem"))).unwrap_err();
        assert!(e.ends_with("contains no certificates"), "{e}");
    }
}
