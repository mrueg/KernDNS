//! The Prometheus web configuration file that `prometheus { tls FILE }`
//! points to: a port of the `web` package of
//! `github.com/prometheus/exporter-toolkit` v0.20.0, the version CoreDNS
//! 1.15.0 serves `/metrics` with.
//!
//! ```yaml
//! tls_server_config:
//!   cert_file: server.crt      # or cert: inline PEM
//!   key_file: server.key       # or key: inline PEM
//!   client_auth_type: RequireAndVerifyClientCert
//!   client_ca_file: ca.crt     # or client_ca: inline PEM
//!   client_allowed_sans: [client.example.org]
//!   min_version: TLS12
//!   max_version: TLS13
//!   cipher_suites: [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
//!   curve_preferences: [X25519]
//! http_server_config:
//!   http2: true
//!   headers: {X-Frame-Options: deny}
//! basic_auth_users:
//!   alice: $2y$10$...          # bcrypt
//! rate_limit:
//!   interval: 1s
//!   burst: 10
//! ```
//!
//! As in the toolkit, relative file paths are relative to the file's
//! directory, the file is read again for every request (headers, users)
//! and the certificates for every TLS handshake, and without any TLS
//! setting the endpoint stays plain HTTP (with headers, users and the rate
//! limit). Differences, all from rustls: TLS 1.0 and 1.1 aren't available
//! (`min_version` below `TLS12` means `TLS12`, a `max_version` below it is
//! an error), nor are the CBC cipher suites (accepted, never negotiated)
//! and `CurveP521` (accepted, not offered).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CipherSuite, NamedGroup};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use serde::{Deserialize, Deserializer};

use crate::tlsconfig::{self, ClientAuth};

/// The parsed file (`web.Config`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    #[serde(deserialize_with = "null_default")]
    tls_server_config: TlsServerConfig,
    #[serde(deserialize_with = "null_zero_http")]
    http_server_config: HttpConfig,
    #[serde(deserialize_with = "null_default")]
    rate_limit: RateLimit,
    #[serde(deserialize_with = "null_default")]
    basic_auth_users: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tls_server_config: TlsServerConfig::default(),
            http_server_config: HttpConfig {
                http2: true,
                headers: HashMap::new(),
            },
            rate_limit: RateLimit::default(),
            basic_auth_users: HashMap::new(),
        }
    }
}

/// `tls_server_config`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct TlsServerConfig {
    #[serde(deserialize_with = "null_default")]
    cert: String,
    #[serde(deserialize_with = "null_default")]
    key: String,
    #[serde(deserialize_with = "null_default")]
    client_ca: String,
    #[serde(deserialize_with = "null_default")]
    cert_file: String,
    #[serde(deserialize_with = "null_default")]
    key_file: String,
    #[serde(deserialize_with = "null_default")]
    client_auth_type: String,
    #[serde(deserialize_with = "null_default")]
    client_ca_file: String,
    #[serde(deserialize_with = "null_default")]
    cipher_suites: Vec<String>,
    #[serde(deserialize_with = "null_default")]
    curve_preferences: Vec<String>,
    #[serde(rename = "min_version", deserialize_with = "null_default")]
    min_version_name: String,
    #[serde(rename = "max_version", deserialize_with = "null_default")]
    max_version_name: String,
    /// `min_version`, `max_version` as numbers (set by [`load`]).
    #[serde(skip)]
    min_version: u16,
    #[serde(skip)]
    max_version: u16,
    /// Parsed and ignored, as in the toolkit.
    #[allow(dead_code)]
    #[serde(deserialize_with = "null_default")]
    prefer_server_cipher_suites: bool,
    /// `None` (absent or null): no check; `Some([])` rejects every
    /// client certificate, as Go's non-nil empty slice does.
    client_allowed_sans: Option<Vec<String>>,
}

const TLS10: u16 = 0x0301;
const TLS11: u16 = 0x0302;
const TLS12: u16 = 0x0303;
const TLS13: u16 = 0x0304;

impl Default for TlsServerConfig {
    fn default() -> Self {
        Self {
            cert: String::new(),
            key: String::new(),
            client_ca: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
            client_auth_type: String::new(),
            client_ca_file: String::new(),
            cipher_suites: Vec::new(),
            curve_preferences: Vec::new(),
            min_version_name: String::new(),
            max_version_name: String::new(),
            min_version: TLS12,
            max_version: TLS13,
            prefer_server_cipher_suites: true,
            client_allowed_sans: None,
        }
    }
}

/// `http_server_config`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpConfig {
    #[serde(default = "yes", deserialize_with = "null_default")]
    http2: bool,
    #[serde(default, deserialize_with = "null_default")]
    headers: HashMap<String, String>,
}

fn yes() -> bool {
    true
}

/// `rate_limit`: `golang.org/x/time/rate` with one token every
/// `interval`, at most `burst` saved up.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RateLimit {
    #[serde(deserialize_with = "null_default")]
    burst: u64,
    #[serde(deserialize_with = "go_duration")]
    interval: Duration,
}

/// YAML null is the zero value, as with yaml.v2.
fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(d: D) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A null `http_server_config` is Go's zero `HTTPConfig`: no HTTP/2.
fn null_zero_http<'de, D: Deserializer<'de>>(d: D) -> Result<HttpConfig, D::Error> {
    Ok(Option::<HttpConfig>::deserialize(d)?.unwrap_or(HttpConfig {
        http2: false,
        headers: HashMap::new(),
    }))
}

/// A `time.Duration` as yaml.v2 reads it: a Go duration string, or an
/// integer number of nanoseconds.
fn go_duration<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Nanos(u64),
        Text(String),
    }
    match Option::<Raw>::deserialize(d)? {
        None => Ok(Duration::ZERO),
        Some(Raw::Nanos(n)) => Ok(Duration::from_nanos(n)),
        Some(Raw::Text(s)) => kerndns_core::duration::parse_duration(&s).map_err(serde::de::Error::custom),
    }
}

/// `web.TLSVersion`.
fn tls_version(s: &str) -> Result<u16, String> {
    match s {
        "TLS13" => Ok(TLS13),
        "TLS12" => Ok(TLS12),
        "TLS11" => Ok(TLS11),
        "TLS10" => Ok(TLS10),
        _ => Err(format!("unknown TLS version: {s}")),
    }
}

/// Go's `tls.CipherSuites()`: the names the toolkit accepts, with the
/// rustls suite (none for CBC, which rustls doesn't implement).
const CIPHERS: &[(&str, Option<CipherSuite>)] = &[
    ("TLS_AES_128_GCM_SHA256", Some(CipherSuite::TLS13_AES_128_GCM_SHA256)),
    ("TLS_AES_256_GCM_SHA384", Some(CipherSuite::TLS13_AES_256_GCM_SHA384)),
    (
        "TLS_CHACHA20_POLY1305_SHA256",
        Some(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
    ),
    ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", None),
    ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", None),
    ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", None),
    ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", None),
    (
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    ),
    (
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    ),
    (
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        Some(CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    ),
    (
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        Some(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    ),
    (
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        Some(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    ),
    (
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        Some(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    ),
];

/// The toolkit's curve names (`CurveP521`: none, ring has no P-521).
const CURVES: &[(&str, Option<NamedGroup>)] = &[
    ("CurveP256", Some(NamedGroup::secp256r1)),
    ("CurveP384", Some(NamedGroup::secp384r1)),
    ("CurveP521", None),
    ("X25519", Some(NamedGroup::X25519)),
];

/// The headers `http_server_config.headers` may set, with their allowed
/// values (`None`: any).
const EXTRA_HEADERS: &[(&str, Option<&[&str]>)] = &[
    ("Strict-Transport-Security", None),
    ("X-Content-Type-Options", Some(&["nosniff"])),
    ("X-Frame-Options", Some(&["deny", "sameorigin"])),
    ("X-XSS-Protection", None),
    ("Content-Security-Policy", None),
];

/// The error of Go's `os.ReadFile`.
fn read_error(path: &str, e: &std::io::Error) -> String {
    let msg = match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        std::io::ErrorKind::IsADirectory => return format!("read {path}: is a directory"),
        _ => e.to_string(),
    };
    format!("open {path}: {msg}")
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| read_error(path, &e))
}

/// `config_util.JoinDir`: a relative, non-empty path is made relative to
/// `dir`.
fn join_dir(dir: &Path, p: &str) -> String {
    if p.is_empty() || Path::new(p).is_absolute() {
        return p.to_string();
    }
    dir.join(p).to_string_lossy().into_owned()
}

/// `getConfig`: read and parse the file (strictly: unknown keys are
/// errors), check the headers and make the file paths relative to it.
pub fn load(path: &str) -> Result<Config, String> {
    let text = read(path)?;
    let text = String::from_utf8(text).map_err(|e| format!("yaml: invalid UTF-8: {e}"))?;
    // the first line: the rest is a source snippet
    let mut c: Config = serde_saphyr::from_str(&text)
        .map_err(|e| format!("yaml: {}", e.to_string().lines().next().unwrap_or_default()))?;
    // the toolkit's custom YAML types fail while parsing, with their own
    // errors
    for name in &c.tls_server_config.cipher_suites {
        if !CIPHERS.iter().any(|(n, _)| n == name) {
            return Err(format!("unknown cipher: {name}"));
        }
    }
    for name in &c.tls_server_config.curve_preferences {
        if !CURVES.iter().any(|(n, _)| n == name) {
            return Err(format!("unknown curve: {name}"));
        }
    }
    let t = &mut c.tls_server_config;
    if !t.min_version_name.is_empty() {
        t.min_version = tls_version(&t.min_version_name)?;
    }
    if !t.max_version_name.is_empty() {
        t.max_version = tls_version(&t.max_version_name)?;
    }
    validate_headers(&c.http_server_config.headers)?;
    let t = &mut c.tls_server_config;
    let dir = Path::new(path).parent().unwrap_or(Path::new(""));
    t.cert_file = join_dir(dir, &t.cert_file);
    t.key_file = join_dir(dir, &t.key_file);
    t.client_ca_file = join_dir(dir, &t.client_ca_file);
    Ok(c)
}

/// `validateHeaderConfig`.
fn validate_headers(headers: &HashMap<String, String>) -> Result<(), String> {
    let mut keys: Vec<_> = headers.keys().collect();
    keys.sort();
    for k in keys {
        let v = &headers[k];
        let Some((_, allowed)) = EXTRA_HEADERS.iter().find(|(h, _)| h == k) else {
            return Err(format!("HTTP header {k:?} can not be configured"));
        };
        if let Some(allowed) = allowed
            && !allowed.contains(&v.as_str())
        {
            let list = allowed.iter().map(|a| format!("{a:?}")).collect::<Vec<_>>().join(" ");
            return Err(format!(
                "invalid value for {k}. Expected one of: [{list}], but got: {v:?}"
            ));
        }
    }
    Ok(())
}

/// `bcrypt.Cost`: check that `hash` is a bcrypt hash, with Go's errors.
fn bcrypt_cost(hash: &str) -> Result<u32, String> {
    let b = hash.as_bytes();
    if b.len() < 59 {
        return Err("crypto/bcrypt: hashedSecret too short to be a bcrypted password".into());
    }
    if b[0] != b'$' {
        return Err(format!(
            "crypto/bcrypt: bcrypt hashes must start with '$', but hashedSecret started with '{}'",
            b[0] as char
        ));
    }
    if b[1] > b'2' {
        return Err(format!(
            "crypto/bcrypt: bcrypt algorithm version '{}' requested is newer than current version '2'",
            b[1] as char
        ));
    }
    let n = if b[2] != b'$' { 4 } else { 3 };
    let digits = std::str::from_utf8(&b[n..n + 2]).unwrap_or("");
    let cost: u32 = digits
        .parse()
        .map_err(|_| format!("strconv.Atoi: parsing {digits:?}: invalid syntax"))?;
    if !(4..=31).contains(&cost) {
        return Err(format!(
            "crypto/bcrypt: cost {cost} is outside allowed inclusive range 4..31"
        ));
    }
    Ok(cost)
}

impl TlsServerConfig {
    /// `IsEnabled`: any TLS setting at all.
    fn enabled(&self) -> bool {
        !(self.cert_file.is_empty()
            && self.cert.is_empty()
            && self.key_file.is_empty()
            && self.key.is_empty()
            && self.client_ca_file.is_empty()
            && self.client_ca.is_empty()
            && self.client_auth_type.is_empty())
    }

    fn load_cert(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
        let cert = if self.cert_file.is_empty() {
            self.cert.as_bytes().to_vec()
        } else {
            read(&self.cert_file).map_err(|e| format!("failed to read cert_file ({}): {e}", self.cert_file))?
        };
        let key = if self.key_file.is_empty() {
            self.key.as_bytes().to_vec()
        } else {
            read(&self.key_file).map_err(|e| format!("failed to read key_file ({}): {e}", self.key_file))?
        };
        let certs: Vec<_> = CertificateDer::pem_slice_iter(&cert)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("failed to load X509KeyPair: {e}"))?;
        if certs.is_empty() {
            return Err("failed to load X509KeyPair: tls: failed to find any PEM data in certificate input".into());
        }
        let key = PrivateKeyDer::from_pem_slice(&key).map_err(|e| match e {
            rustls_pki_types::pem::Error::NoItemsFound => {
                "failed to load X509KeyPair: tls: failed to find any PEM data in key input".to_string()
            }
            e => format!("failed to load X509KeyPair: {e}"),
        })?;
        Ok((certs, key))
    }

    fn client_auth(&self) -> Result<ClientAuth, String> {
        Ok(match self.client_auth_type.as_str() {
            "RequestClientCert" => ClientAuth::Request,
            "RequireAnyClientCert" | "RequireClientCert" => ClientAuth::Require,
            "VerifyClientCertIfGiven" => ClientAuth::VerifyIfGiven,
            "RequireAndVerifyClientCert" => ClientAuth::RequireAndVerify,
            "" | "NoClientCert" => ClientAuth::NoCert,
            other => return Err(format!("invalid ClientAuth: {other}")),
        })
    }

    /// The client CAs (`None`: the system roots, as for a nil
    /// `ClientCAs`). Like `AppendCertsFromPEM`, what doesn't parse is
    /// skipped.
    fn client_cas(&self) -> Result<Option<rustls::RootCertStore>, String> {
        let pem = if !self.client_ca_file.is_empty() {
            read(&self.client_ca_file)?
        } else if !self.client_ca.is_empty() {
            self.client_ca.as_bytes().to_vec()
        } else {
            return Ok(None);
        };
        let mut store = rustls::RootCertStore::empty();
        store.add_parsable_certificates(CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok));
        Ok(Some(store))
    }

    /// `ConfigToTLSConfig`: `Ok(None)` is `errNoTLSConfig` (plain HTTP).
    fn server_config(&self, http2: bool) -> Result<Option<Arc<rustls::ServerConfig>>, String> {
        if !self.enabled() {
            return Ok(None);
        }
        if self.cert_file.is_empty() && self.cert.is_empty() {
            return Err("missing one of cert or cert_file".into());
        }
        if self.key_file.is_empty() && self.key.is_empty() {
            return Err("missing one of key or key_file".into());
        }
        let (certs, key) = self.load_cert()?;
        let cas = self.client_cas()?;
        let auth = self.client_auth()?;
        if cas.is_some() && auth == ClientAuth::NoCert {
            return Err("client CA's have been configured without a Client Auth Policy".into());
        }

        tlsconfig::install_provider();
        let mut provider = rustls::crypto::ring::default_provider();
        // Go applies the list to TLS 1.0-1.2 only
        if !self.cipher_suites.is_empty() {
            let wanted: Vec<CipherSuite> = self
                .cipher_suites
                .iter()
                .filter_map(|n| CIPHERS.iter().find(|(c, _)| c == n).and_then(|(_, s)| *s))
                .collect();
            provider.cipher_suites.retain(|s| match s {
                rustls::SupportedCipherSuite::Tls13(_) => true,
                rustls::SupportedCipherSuite::Tls12(_) => wanted.contains(&s.suite()),
            });
        }
        if !self.curve_preferences.is_empty() {
            let wanted: Vec<NamedGroup> = self
                .curve_preferences
                .iter()
                .filter_map(|n| CURVES.iter().find(|(c, _)| c == n).and_then(|(_, g)| *g))
                .collect();
            provider.kx_groups = wanted
                .iter()
                .filter_map(|g| provider.kx_groups.iter().find(|k| k.name() == *g).copied())
                .collect();
            if provider.kx_groups.is_empty() {
                return Err("none of curve_preferences is supported (CurveP521 isn't)".into());
            }
        }
        let min = self.min_version.max(TLS12);
        if self.max_version < TLS12 {
            return Err("max_version below TLS12 is not supported".into());
        }
        let mut versions = Vec::new();
        if min <= TLS13 && self.max_version >= TLS13 {
            versions.push(&rustls::version::TLS13);
        }
        if min <= TLS12 {
            versions.push(&rustls::version::TLS12);
        }
        if versions.is_empty() {
            return Err("tls: no supported versions satisfy MinVersion and MaxVersion".into());
        }
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&versions)
            .map_err(|e| e.to_string())?;
        let verifier = tlsconfig::client_verifier_with_roots(cas, auth)?;
        let verifier = match (verifier, &self.client_allowed_sans) {
            (Some(v), Some(sans)) => Some(Arc::new(AllowedSans {
                inner: v,
                sans: sans.clone(),
            }) as Arc<dyn ClientCertVerifier>),
            (v, _) => v,
        };
        let builder = match verifier {
            None => builder.with_no_client_auth(),
            Some(v) => builder.with_client_cert_verifier(v),
        };
        let mut cfg = builder
            .with_single_cert(certs, key)
            .map_err(|e| format!("failed to load X509KeyPair: {e}"))?;
        cfg.alpn_protocols = if http2 {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        Ok(Some(Arc::new(cfg)))
    }

    /// The check `http.Server.ServeTLS` makes when HTTP/2 is on: a TLS 1.2
    /// cipher list must have one of the HTTP/2-required suites.
    fn check_http2_ciphers(&self) -> Result<(), String> {
        if self.cipher_suites.is_empty() || self.min_version >= TLS13 {
            return Ok(());
        }
        let ok = self
            .cipher_suites
            .iter()
            .any(|c| c == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" || c == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        if ok {
            return Ok(());
        }
        Err("http2: TLSConfig.CipherSuites is missing an HTTP/2-required AES_128_GCM_SHA256 cipher (need at least one of TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)".into())
    }
}

/// Requires a client certificate with one of the allowed SANs
/// (`VerifyPeerCertificate`). Go calls the check for every handshake that
/// asks for a certificate, and it fails without one, so the certificate is
/// mandatory here.
#[derive(Debug)]
struct AllowedSans {
    inner: Arc<dyn ClientCertVerifier>,
    sans: Vec<String>,
}

impl ClientCertVerifier for AllowedSans {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let ok = self.inner.verify_client_cert(end_entity, intermediates, now)?;
        let found = cert_sans(end_entity)
            .map_err(|e| rustls::Error::General(format!("error parsing client certificate: {e}")))?;
        if found.iter().any(|s| self.sans.contains(s)) {
            return Ok(ok);
        }
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
            rustls::OtherError(Arc::new(SanError(format!(
                "could not find allowed SANs in client cert, found: [{}]",
                self.sans.join(" ")
            )))),
        )))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct SanError(String);

impl std::fmt::Display for SanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SanError {}

/// The SAN values Go compares: DNS names, email addresses, IP addresses
/// and URIs.
fn cert_sans(der: &CertificateDer<'_>) -> Result<Vec<String>, String> {
    use x509_parser::extensions::GeneralName;
    let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).map_err(|e| e.to_string())?;
    let Some(san) = cert.subject_alternative_name().map_err(|e| e.to_string())? else {
        return Ok(Vec::new());
    };
    let (mut dns, mut email, mut ip, mut uri) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for n in &san.value.general_names {
        match n {
            GeneralName::DNSName(s) => dns.push(s.to_string()),
            GeneralName::RFC822Name(s) => email.push(s.to_string()),
            GeneralName::IPAddress(b) => match b.len() {
                4 => ip.push(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*b).unwrap()).to_string()),
                16 => ip.push(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*b).unwrap()).to_string()),
                _ => {}
            },
            GeneralName::URI(s) => uri.push(s.to_string()),
            _ => {}
        }
    }
    Ok([dns, email, ip, uri].concat())
}

/// `web.Validate`: everything that can be checked before serving.
pub fn validate(path: &str) -> Result<(), String> {
    let c = load(path)?;
    let mut users: Vec<_> = c.basic_auth_users.iter().collect();
    users.sort();
    for (_, hash) in users {
        bcrypt_cost(hash)?;
    }
    c.tls_server_config.server_config(c.http_server_config.http2)?;
    Ok(())
}

/// What serving needs, read once at startup (`web.Serve`): the rest is
/// read again for every request and handshake.
pub struct Web {
    path: String,
    http2: bool,
    tls: bool,
    limiter: Option<Mutex<Limiter>>,
    cache: Mutex<HashMap<(String, String, String), bool>>,
}

impl Web {
    /// Validate the file and prepare to serve with it. The error is the
    /// line CoreDNS logs: `Invalid TLS config: ...` (`web.Validate`), or
    /// `Failed to start HTTPS metrics server: ...` (`web.Serve`).
    pub fn new(path: &str) -> Result<Web, String> {
        validate(path).map_err(|e| format!("Invalid TLS config: {e}"))?;
        let c = load(path).map_err(|e| format!("Invalid TLS config: {e}"))?;
        let tls = c.tls_server_config.enabled();
        if tls && c.http_server_config.http2 {
            c.tls_server_config
                .check_http2_ciphers()
                .map_err(|e| format!("Failed to start HTTPS metrics server: {e}"))?;
        }
        let r = &c.rate_limit;
        let limiter = (!r.interval.is_zero()).then(|| Mutex::new(Limiter::new(r.interval, r.burst)));
        Ok(Web {
            path: path.to_string(),
            http2: c.http_server_config.http2,
            tls,
            limiter,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Serve HTTPS (TLS settings were present at startup).
    pub fn tls(&self) -> bool {
        self.tls
    }

    /// Offer HTTP/2 over TLS.
    pub fn http2(&self) -> bool {
        self.tls && self.http2
    }

    /// The TLS config for a new connection, from the file as it is now
    /// (`GetConfigForClient`).
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        let c = load(&self.path)?;
        c.tls_server_config
            .server_config(self.http2)?
            .ok_or_else(|| "TLS config is not present".to_string())
    }

    /// The `webHandler` checks for one request: `Ok` with the headers to
    /// add to the response, or the error response to send instead.
    pub async fn check(&self, authorization: Option<&str>) -> Result<Vec<(String, String)>, Refusal> {
        let c = match load(&self.path) {
            Ok(c) => c,
            Err(e) => {
                kerndns_core::error!("Unable to parse configuration: {}", e);
                return Err(Refusal::status(500, "Internal Server Error"));
            }
        };
        if let Some(l) = &self.limiter
            && !l.lock().unwrap().allow()
        {
            return Err(Refusal::status(429, "Too Many Requests"));
        }
        let mut headers: Vec<(String, String)> = c.http_server_config.headers.into_iter().collect();
        headers.sort();
        if c.basic_auth_users.is_empty() {
            return Ok(headers);
        }
        if let Some((user, pass)) = authorization.and_then(basic_auth) {
            let (hash, valid_user) = match c.basic_auth_users.get(&user) {
                Some(h) => (h.clone(), true),
                // a fixed hash, so unknown users take as long
                None => (
                    "$2y$10$QOauhQNbBCuQDKes6eFzPeMqBSjb7Mr5DUmpZ/VcEd00UAV/LDeSi".to_string(),
                    false,
                ),
            };
            let key = (user, hash.clone(), pass.clone());
            let cached = self.cache.lock().unwrap().get(&key).copied();
            let ok = match cached {
                Some(ok) => ok,
                None => {
                    let ok = valid_user && self.bcrypt_matches(&hash, &pass).await;
                    let mut cache = self.cache.lock().unwrap();
                    make_room(&mut cache);
                    cache.insert(key, ok);
                    ok
                }
            };
            if ok && valid_user {
                return Ok(headers);
            }
        }
        let mut r = Refusal::status(401, "Unauthorized");
        r.headers = headers;
        r.headers.push(("WWW-Authenticate".into(), "Basic".into()));
        Err(r)
    }

    /// `bcrypt.CompareHashAndPassword`, one at a time (it is expensive)
    /// and off the async workers.
    async fn bcrypt_matches(&self, hash: &str, pass: &str) -> bool {
        static ONE: Mutex<()> = Mutex::new(());
        let (hash, pass) = (hash.to_string(), pass.to_string());
        tokio::task::spawn_blocking(move || {
            let _one = ONE.lock().unwrap();
            bcrypt::verify(&pass, &hash).unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    }
}

/// The toolkit's cache holds 100 entries and drops about a tenth of them,
/// at random, when full.
fn make_room<K: Clone + Eq + std::hash::Hash, V>(cache: &mut HashMap<K, V>) {
    if cache.len() < 100 {
        return;
    }
    let n = (cache.len() / 10).max(1);
    // HashMap iteration order is randomized per map
    let victims: Vec<K> = cache.keys().take(n + 1).cloned().collect();
    for k in victims {
        cache.remove(&k);
    }
}

/// `Request.BasicAuth`.
fn basic_auth(header: &str) -> Option<(String, String)> {
    let (scheme, rest) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = data_encoding::BASE64.decode(rest.as_bytes()).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

/// An error response, as Go's `http.Error` writes it.
pub struct Refusal {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}

impl Refusal {
    fn status(status: u16, text: &str) -> Refusal {
        Refusal {
            status,
            body: format!("{text}\n"),
            headers: Vec::new(),
        }
    }
}

/// A token bucket like `rate.NewLimiter(rate.Every(interval), burst)`:
/// starts full, one token per interval, at most `burst`.
struct Limiter {
    interval: Duration,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl Limiter {
    fn new(interval: Duration, burst: u64) -> Limiter {
        Limiter {
            interval,
            burst: burst as f64,
            tokens: burst as f64,
            last: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let earned = now.duration_since(self.last).as_secs_f64() / self.interval.as_secs_f64();
        self.tokens = (self.tokens + earned).min(self.burst);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests;
