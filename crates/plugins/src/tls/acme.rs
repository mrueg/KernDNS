//! ACME certificates for the `tls` plugin (`tls { acme DOMAIN... }`), a
//! port of CoreDNS's `plugin/tls/acme.go`.
//!
//! CoreDNS hands the work to certmagic; KernDNS uses `instant-acme` for the
//! protocol and does the rest itself:
//!
//! - setup parses and validates the options and registers the block's
//!   configuration with a runtime shared by the whole Corefile;
//! - the first ACME block adds a DNS-01 challenge handler to every server
//!   block, which answers `_acme-challenge` TXT queries from the records
//!   the issuer presents;
//! - at startup (after all listeners are up) stored certificates are
//!   loaded and a task per configuration obtains missing certificates and
//!   renews them when a third of their lifetime is left;
//! - listeners get a rustls config whose certificate resolver reads the
//!   current certificate, so renewals apply without a restart.
//!
//! Storage follows certmagic's file layout, so KernDNS and CoreDNS can use
//! the same directory.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock, Weak};

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::rdata::TXT;
use kerndns_core::proto::rr::{DNSClass, RData, Record, RecordType};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, Request, ResponseWriter, SetupError, async_trait,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use super::issuer;

/// certmagic's default CA: Let's Encrypt production.
pub const DEFAULT_CA: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// The options of one `tls { acme ... }` block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcmeOptions {
    pub domains: Vec<String>,
    pub email: String,
    pub ca: String,
    pub storage: PathBuf,
    pub ca_root: Option<PathBuf>,
    pub resolver: Option<String>,
}

impl AcmeOptions {
    /// Blocks with equal keys share one certificate manager (CoreDNS's
    /// `acmeConfigKey`).
    fn key(&self) -> String {
        let mut domains = self.domains.clone();
        domains.sort();
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            domains.join("\x01"),
            self.email,
            self.ca,
            self.storage.display(),
            self.ca_root
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            self.resolver.as_deref().unwrap_or_default()
        )
    }
}

/// Go's `%q` for the strings in error messages.
fn q(s: &str) -> String {
    format!("{s:?}")
}

/// Lowercase, strip the trailing dot, convert to ASCII (IDNA) and check
/// the name, like `normalizeACMEDomain`. A leading `*.` is kept.
pub fn normalize_domain(domain: &str) -> Result<String, String> {
    let domain = domain.strip_suffix('.').unwrap_or(domain).to_lowercase();
    let wildcard = domain.starts_with("*.");
    let check = domain.strip_prefix("*.").unwrap_or(&domain);
    if domain.is_empty() || check.is_empty() || check.contains('*') || check.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!("invalid ACME domain {}", q(&domain)));
    }
    let ascii =
        idna::domain_to_ascii_strict(check).map_err(|e| format!("invalid ACME domain {}: idna: {e}", q(&domain)))?;
    if !is_domain_name(&ascii) {
        return Err(format!("invalid ACME domain {}", q(&domain)));
    }
    Ok(if wildcard { format!("*.{ascii}") } else { ascii })
}

/// miekg/dns `IsDomainName` for a name without escapes: labels of 1–63
/// octets, at most 255 octets on the wire.
fn is_domain_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty() && name.len() + 2 <= 255 && name.split('.').all(|l| !l.is_empty() && l.len() <= 63)
}

/// Check and normalize the options, like `validateACMEOptions`.
pub fn validate(o: &mut AcmeOptions) -> Result<(), String> {
    if o.domains.is_empty() {
        return Err("ACME requires at least one domain".into());
    }
    let mut domains: Vec<String> = Vec::with_capacity(o.domains.len());
    for d in &o.domains {
        let n = normalize_domain(d)?;
        if !domains.contains(&n) {
            domains.push(n);
        }
    }
    o.domains = domains;

    let ok =
        o.ca.parse::<http::Uri>().ok().is_some_and(|u| {
            matches!(u.scheme_str(), Some("http" | "https")) && u.host().is_some_and(|h| !h.is_empty())
        });
    if !ok {
        return Err(format!("invalid ACME CA URL {}", q(&o.ca)));
    }
    if let Some(r) = &o.resolver {
        let (host, port) = split_host_port(r).map_err(|e| format!("invalid ACME resolver {}: {e}", q(r)))?;
        if host.is_empty() {
            return Err(format!("invalid ACME resolver {}: host is empty", q(r)));
        }
        if !port.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p)) {
            return Err(format!("invalid ACME resolver port {}", q(port)));
        }
    }
    if let Some(root) = &o.ca_root {
        issuer::load_roots(root)?;
    }
    Ok(())
}

/// Go's `net.SplitHostPort`, with its error texts.
fn split_host_port(s: &str) -> Result<(&str, &str), String> {
    let missing = || format!("address {s}: missing port in address");
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("address {s}: missing ']' in address"))?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':').ok_or_else(missing)?;
        if port.contains(':') {
            return Err(format!("address {s}: too many colons in address"));
        }
        return Ok((host, port));
    }
    let i = s.rfind(':').ok_or_else(missing)?;
    let (host, port) = (&s[..i], &s[i + 1..]);
    if host.contains(':') {
        return Err(format!("address {s}: too many colons in address"));
    }
    Ok((host, port))
}

/// Make `path` absolute, relative to `root` if given (`resolveACMEPath`).
fn resolve_path(root: Option<&Path>, path: &str) -> Result<PathBuf, String> {
    let mut p = PathBuf::from(path);
    if p.is_relative()
        && let Some(root) = root
    {
        p = root.join(p);
    }
    std::path::absolute(&p).map_err(|e| format!("resolving ACME path {}: {e}", q(&p.display().to_string())))
}

/// Parse `tls { acme ... }` (the `tls` line had no arguments) and return
/// the listener's TLS config, like `parseACMETLS`.
pub fn parse(c: &mut Controller<'_>) -> Result<Arc<rustls::ServerConfig>, SetupError> {
    let root = c.config.root.clone();
    let tls_err = |e: String| SetupError::new("tls", e);
    let mut o = AcmeOptions {
        ca: DEFAULT_CA.into(),
        storage: resolve_path(
            None,
            &root
                .as_deref()
                .unwrap_or(Path::new("."))
                .join(".coredns")
                .join("acme")
                .display()
                .to_string(),
        )
        .map_err(|e| tls_err(e.replace("resolving ACME path", "resolving ACME storage directory")))?,
        ..Default::default()
    };
    let mut seen: Vec<String> = Vec::new();
    while c.next_block() {
        let name = c.val().to_string();
        let args = c.remaining_args();
        if seen.contains(&name) {
            return Err(c.errf(format!("ACME option {} can only be specified once", q(&name))));
        }
        seen.push(name.clone());
        let one = |c: &Controller<'_>| -> Result<String, SetupError> {
            match args.as_slice() {
                [a] => Ok(a.clone()),
                _ => Err(c.arg_err()),
            }
        };
        match name.as_str() {
            "acme" => {
                if args.is_empty() {
                    return Err(c.arg_err());
                }
                o.domains = args.clone();
            }
            "email" => o.email = one(c)?,
            "ca" => o.ca = one(c)?,
            "storage" => o.storage = resolve_path(root.as_deref(), &one(c)?).map_err(tls_err)?,
            "ca_root" => o.ca_root = Some(resolve_path(root.as_deref(), &one(c)?).map_err(tls_err)?),
            "resolver" => o.resolver = Some(one(c)?),
            _ => return Err(c.errf(format!("unknown ACME option {}", q(&name)))),
        }
    }
    validate(&mut o).map_err(tls_err)?;

    let rt = runtime(c);
    let entry = rt.add(o).map_err(tls_err)?;
    rt.install_challenge_handlers(c);
    Ok(entry.tls.clone())
}

// ---------------------------------------------------------------------------
// DNS-01 challenges

/// The TXT records of pending DNS-01 challenges (`acmeDNS01Solver`).
/// Values are counted so that two challenges with the same value can be
/// presented and cleaned up independently.
#[derive(Debug, Default)]
pub struct Solver {
    records: RwLock<HashMap<String, BTreeMap<String, usize>>>,
}

fn challenge_name(name: &str) -> String {
    let mut n = name.to_lowercase();
    if !n.ends_with('.') {
        n.push('.');
    }
    n
}

impl Solver {
    pub fn present(&self, name: &str, value: &str) {
        let mut r = self.records.write().unwrap();
        *r.entry(challenge_name(name))
            .or_default()
            .entry(value.to_string())
            .or_default() += 1;
    }

    pub fn cleanup(&self, name: &str, value: &str) {
        let name = challenge_name(name);
        let mut r = self.records.write().unwrap();
        let Some(values) = r.get_mut(&name) else { return };
        match values.get_mut(value) {
            Some(n) if *n > 1 => *n -= 1,
            _ => {
                values.remove(value);
            }
        }
        if values.is_empty() {
            r.remove(&name);
        }
    }

    /// The values for `name`, sorted.
    pub fn values(&self, name: &str) -> Vec<String> {
        let r = self.records.read().unwrap();
        r.get(&challenge_name(name))
            .map(|v| v.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Answers TXT queries for presented challenges and passes everything else
/// on (`acmeChallengeHandler`). It is in every server block.
pub struct ChallengeHandler {
    next: Next,
    solver: Arc<Solver>,
}

#[async_trait]
impl Handler for ChallengeHandler {
    fn name(&self) -> &'static str {
        "tls"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        if req.msg.queries.len() != 1 || req.qtype() != RecordType::TXT || req.qclass() != DNSClass::IN {
            return kerndns_core::next_or_failure("tls", &self.next, ctx, w, req).await;
        }
        let values = self.solver.values(&req.name());
        if values.is_empty() {
            return kerndns_core::next_or_failure("tls", &self.next, ctx, w, req).await;
        }
        let mut m = req.reply();
        m.metadata.authoritative = true;
        for v in values {
            m.answers.push(Record::from_rdata(
                req.qname().clone(),
                0,
                RData::TXT(TXT::try_from(v).expect("a digest of 43 bytes")),
            ));
        }
        w.write_msg(m)
            .await
            .map_err(|e| PluginError::servfail("tls", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

// ---------------------------------------------------------------------------
// Certificates served to clients

/// A managed certificate with its validity (Unix seconds).
pub struct Managed {
    pub key: Arc<CertifiedKey>,
    pub not_before: i64,
    pub not_after: i64,
}

impl Managed {
    /// When to renew: with a third of the lifetime left (certmagic's
    /// default `RenewalWindowRatio`).
    pub fn renew_at(&self) -> i64 {
        self.not_after - (self.not_after - self.not_before) / 3
    }
}

/// The current certificates of one ACME configuration, by domain. The
/// listeners' rustls configs resolve certificates here, so a renewal
/// replaces the certificate for every new handshake.
#[derive(Default)]
pub struct CertStore {
    domains: Vec<String>,
    certs: RwLock<HashMap<String, Arc<Managed>>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore").field("domains", &self.domains).finish()
    }
}

/// certmagic's `MatchWildcard`: `*.example.org` matches one label.
fn match_wildcard(name: &str, pattern: &str) -> bool {
    if name == pattern {
        return true;
    }
    let Some(base) = pattern.strip_prefix("*.") else {
        return false;
    };
    name.split_once('.')
        .is_some_and(|(label, rest)| !label.is_empty() && rest == base)
}

impl CertStore {
    fn new(domains: Vec<String>) -> Self {
        Self {
            domains,
            certs: RwLock::default(),
        }
    }

    pub fn get(&self, domain: &str) -> Option<Arc<Managed>> {
        self.certs.read().unwrap().get(domain).cloned()
    }

    pub fn set(&self, domain: &str, m: Managed) {
        self.certs.write().unwrap().insert(domain.to_string(), Arc::new(m));
    }

    fn manages(&self, server_name: &str) -> bool {
        let Ok(name) = normalize_domain(server_name) else {
            return false;
        };
        self.domains.iter().any(|d| match_wildcard(&name, d))
    }

    /// The certificate for a TLS server name (or the first domain's without
    /// SNI), like certmagic's `GetCertificate`: an exact match first, then
    /// a wildcard certificate.
    pub fn lookup(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let name = match server_name {
            Some(sni) if !sni.is_empty() => {
                if !self.manages(sni) {
                    return None;
                }
                normalize_domain(sni).ok()?
            }
            _ => self.domains.first()?.clone(),
        };
        let certs = self.certs.read().unwrap();
        if let Some(m) = certs.get(&name) {
            return Some(m.key.clone());
        }
        let (_, rest) = name.split_once('.')?;
        certs.get(&format!("*.{rest}")).map(|m| m.key.clone())
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(hello.server_name())
    }
}

/// Stores by configuration key, so a listener kept across a reload (which
/// keeps its TLS config) sees the certificates the new instance renews.
static STORES: Mutex<Vec<(String, Weak<CertStore>)>> = Mutex::new(Vec::new());

fn shared_store(key: &str, domains: &[String]) -> Arc<CertStore> {
    let mut stores = STORES.lock().unwrap();
    stores.retain(|(_, w)| w.strong_count() > 0);
    if let Some(s) = stores.iter().find(|(k, _)| k == key).and_then(|(_, w)| w.upgrade()) {
        return s;
    }
    let s = Arc::new(CertStore::new(domains.to_vec()));
    stores.push((key.to_string(), Arc::downgrade(&s)));
    s
}

// ---------------------------------------------------------------------------
// The runtime shared by all blocks of one Corefile load

/// One ACME configuration and the TLS config of its listeners.
pub struct Entry {
    pub options: AcmeOptions,
    key: String,
    pub store: Arc<CertStore>,
    pub tls: Arc<rustls::ServerConfig>,
}

#[derive(Default)]
struct State {
    entries: Vec<Arc<Entry>>,
    domain_owners: HashMap<String, String>,
    handlers_installed: bool,
    started: bool,
    stopped: bool,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// `acmeRuntime`: the ACME configurations of one Corefile load and the
/// challenge records their issuers present.
#[derive(Default)]
pub struct Runtime {
    state: Mutex<State>,
    pub solver: Arc<Solver>,
}

#[derive(Clone)]
struct RuntimeRef(Arc<Runtime>);

/// The load's runtime, created (with its startup and shutdown hooks) by
/// the first ACME block.
fn runtime(c: &mut Controller<'_>) -> Arc<Runtime> {
    if let Some(r) = c.instance_storage().get::<RuntimeRef>() {
        return r.0.clone();
    }
    let rt = Arc::new(Runtime::default());
    c.instance_storage().insert(RuntimeRef(rt.clone()));
    let start = rt.clone();
    c.on_startup(move || {
        start.start();
        Ok(())
    });
    let stop = rt.clone();
    c.on_shutdown(move || stop.stop());
    rt
}

impl Runtime {
    /// Register a configuration; equal ones share an entry (and so a TLS
    /// config), a domain may not be in two different ones.
    pub fn add(&self, options: AcmeOptions) -> Result<Arc<Entry>, String> {
        let mut st = self.state.lock().unwrap();
        if st.started {
            return Err("cannot add ACME configuration after startup".into());
        }
        let key = options.key();
        if let Some(e) = st.entries.iter().find(|e| e.key == key) {
            return Ok(e.clone());
        }
        for d in &options.domains {
            if st.domain_owners.get(d).is_some_and(|owner| *owner != key) {
                return Err(format!("ACME domain {} is configured with conflicting options", q(d)));
            }
        }
        crate::tlsconfig::install_provider();
        let store = shared_store(&key, &options.domains);
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(store.clone());
        let entry = Arc::new(Entry {
            options,
            key: key.clone(),
            store,
            tls: Arc::new(tls),
        });
        for d in &entry.options.domains {
            st.domain_owners.insert(d.clone(), key.clone());
        }
        st.entries.push(entry.clone());
        Ok(entry)
    }

    /// Add the challenge handler to every server block, once.
    fn install_challenge_handlers(&self, c: &mut Controller<'_>) {
        let mut st = self.state.lock().unwrap();
        if st.handlers_installed {
            return;
        }
        st.handlers_installed = true;
        let solver = self.solver.clone();
        c.add_plugin_to_all_blocks(move |next| {
            Arc::new(ChallengeHandler {
                next,
                solver: solver.clone(),
            })
        });
    }

    /// Load stored certificates and start managing them in the background
    /// (CoreDNS does this on the instance startup event). Errors are
    /// logged, as caddy does for event hooks.
    pub fn start(self: &Arc<Self>) {
        let mut st = self.state.lock().unwrap();
        if st.started || st.stopped {
            return;
        }
        st.started = true;
        for e in &st.entries {
            if let Err(err) = issuer::load_managed(e) {
                kerndns_core::error!(
                    plugin = "tls",
                    "loading managed certificates for {:?}: {err}",
                    e.options.domains
                );
                return;
            }
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            kerndns_core::error!(plugin = "tls", "ACME certificate management needs a running server");
            return;
        };
        let tasks: Vec<_> = st
            .entries
            .iter()
            .map(|e| handle.spawn(issuer::manage(e.clone(), self.solver.clone())))
            .collect();
        st.tasks = tasks;
    }

    pub fn stop(&self) {
        let mut st = self.state.lock().unwrap();
        st.stopped = true;
        for t in st.tasks.drain(..) {
            t.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::proto::rr::RecordType;

    #[test]
    fn domains() {
        assert_eq!(normalize_domain("DNS.Example.").unwrap(), "dns.example");
        assert_eq!(normalize_domain("*.Example.org").unwrap(), "*.example.org");
        assert_eq!(normalize_domain("bücher.example").unwrap(), "xn--bcher-kva.example");
        for bad in [
            "",
            ".",
            "*.",
            "a.*.b",
            "*.*.b",
            "192.0.2.1",
            "::1",
            "a..b",
            "under_score.example",
        ] {
            assert!(normalize_domain(bad).is_err(), "{bad}");
        }
        assert_eq!(
            normalize_domain("192.0.2.1").unwrap_err(),
            "invalid ACME domain \"192.0.2.1\""
        );
        assert!(match_wildcard("a.example.org", "*.example.org"));
        assert!(!match_wildcard("a.b.example.org", "*.example.org"));
        assert!(!match_wildcard("example.org", "*.example.org"));
    }

    fn opts(domains: &[&str]) -> AcmeOptions {
        AcmeOptions {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            ca: DEFAULT_CA.into(),
            storage: "/tmp/x".into(),
            ..Default::default()
        }
    }

    #[test]
    fn validation() {
        let mut o = opts(&["A.example", "a.example.", "b.example"]);
        validate(&mut o).unwrap();
        assert_eq!(o.domains, vec!["a.example", "b.example"]);
        assert_eq!(
            validate(&mut opts(&[])).unwrap_err(),
            "ACME requires at least one domain"
        );
        for ca in ["ftp://x/dir", "https:///dir", "not a url"] {
            let mut o = opts(&["a.example"]);
            o.ca = ca.into();
            assert_eq!(validate(&mut o).unwrap_err(), format!("invalid ACME CA URL {ca:?}"));
        }
        let resolver = |r: &str| {
            let mut o = opts(&["a.example"]);
            o.resolver = Some(r.into());
            validate(&mut o)
        };
        assert!(resolver("127.0.0.1:53").is_ok());
        assert!(resolver("[::1]:53").is_ok());
        assert_eq!(
            resolver("127.0.0.1").unwrap_err(),
            "invalid ACME resolver \"127.0.0.1\": address 127.0.0.1: missing port in address"
        );
        assert_eq!(
            resolver(":53").unwrap_err(),
            "invalid ACME resolver \":53\": host is empty"
        );
        assert_eq!(resolver("h:0").unwrap_err(), "invalid ACME resolver port \"0\"");
        assert_eq!(resolver("h:dns").unwrap_err(), "invalid ACME resolver port \"dns\"");
        let mut o = opts(&["a.example"]);
        o.ca_root = Some("/nonexistent/root.pem".into());
        assert!(
            validate(&mut o)
                .unwrap_err()
                .starts_with("reading ACME CA root \"/nonexistent/root.pem\": ")
        );
    }

    #[test]
    fn setup() {
        let (res, cfg) = run_setup(
            &super::super::Setup,
            "tls {\n acme dns.example\n email a@b.example\n ca https://ca.example/dir\n storage /tmp/acme-x\n resolver 127.0.0.1:53\n}",
        );
        res.unwrap();
        assert!(cfg.tls.is_some());
        let err = |s: &str| setup_err(&super::super::Setup, s);
        assert_eq!(err("tls"), "plugin/tls: ACME requires at least one domain");
        assert_eq!(
            err("tls {\n acme a.example\n acme b.example\n}"),
            "plugin/tls: Corefile:4 - Error during parsing: ACME option \"acme\" can only be specified once"
        );
        assert_eq!(
            err("tls {\n acme a.example\n bogus x\n}"),
            "plugin/tls: Corefile:4 - Error during parsing: unknown ACME option \"bogus\""
        );
        assert!(err("tls {\n acme\n}").contains("Wrong argument count"));
        assert!(err("tls {\n acme a.example\n email\n}").contains("Wrong argument count"));
        assert!(err("tls {\n acme a.example\n email a b\n}").contains("Wrong argument count"));
        assert_eq!(
            err("tls {\n acme 192.0.2.1\n}"),
            "plugin/tls: invalid ACME domain \"192.0.2.1\""
        );
    }

    #[test]
    fn runtime_entries() {
        let rt = Runtime::default();
        let a = rt.add(opts(&["a.example"])).unwrap();
        let again = rt.add(opts(&["a.example"])).unwrap();
        assert!(Arc::ptr_eq(&a.tls, &again.tls));
        let mut other = opts(&["a.example", "b.example"]);
        other.email = "x@example".into();
        assert_eq!(
            rt.add(other).err().unwrap(),
            "ACME domain \"a.example\" is configured with conflicting options"
        );
    }

    #[test]
    fn solver_counts_values() {
        let s = Solver::default();
        s.present("_acme-challenge.Dns.Example", "v1");
        s.present("_acme-challenge.dns.example.", "v1");
        s.present("_acme-challenge.dns.example.", "v0");
        assert_eq!(s.values("_ACME-challenge.dns.example."), vec!["v0", "v1"]);
        s.cleanup("_acme-challenge.dns.example", "v1");
        assert_eq!(s.values("_acme-challenge.dns.example."), vec!["v0", "v1"]);
        s.cleanup("_acme-challenge.dns.example", "v1");
        s.cleanup("_acme-challenge.dns.example", "v0");
        assert!(s.values("_acme-challenge.dns.example.").is_empty());
        assert!(s.records.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn challenge_handler() {
        let solver = Arc::new(Solver::default());
        let next: Next = Some(Arc::new(crate::whoami::Whoami));
        let h = ChallengeHandler {
            next,
            solver: solver.clone(),
        };
        let req = query("_acme-challenge.dns.example.", RecordType::TXT, "127.0.0.1:5353");
        // nothing presented: the next plugin answers
        let (_, w) = serve(&h, &req).await;
        assert!(w.msg().unwrap().answers.is_empty());

        solver.present("_acme-challenge.dns.example", "token-b");
        solver.present("_acme-challenge.dns.example", "token-a");
        let (rc, w) = serve(&h, &req).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        let m = w.msg().unwrap();
        assert!(m.metadata.authoritative);
        let answers: Vec<_> = m.answers.iter().map(|r| r.to_string()).collect();
        assert_eq!(
            answers,
            vec![
                "_acme-challenge.dns.example. 0 IN TXT token-a",
                "_acme-challenge.dns.example. 0 IN TXT token-b"
            ]
        );
        // other types go on
        let req = query("_acme-challenge.dns.example.", RecordType::A, "127.0.0.1:5353");
        let (_, w) = serve(&h, &req).await;
        assert!(w.msg().unwrap().answers.is_empty());
    }
}
