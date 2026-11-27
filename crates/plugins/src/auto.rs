//! `auto`: serves zones from master files found in a directory, picking up
//! new, changed and removed files. Port of `plugin/auto`.
//!
//! ```text
//! auto [ZONES...] {
//!     directory DIR [REGEXP ORIGIN_TEMPLATE]
//!     reload DURATION
//! }
//! ```
//!
//! Every file under DIR whose name matches REGEXP (default `db\.(.*)`) is
//! loaded as the zone that ORIGIN_TEMPLATE (default `{1}`) expands to. The
//! directory is scanned again every `reload` interval (default 1m, `0`
//! disables it), and each loaded zone reloads its file when its SOA serial
//! changes, like `file`. Zones are transfer sources for `transfer`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kerndns_core::duration::parse_duration;
use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_core::transfer::{TransferError, TransferRegistry, Transferer};
use kerndns_core::zones;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};
use regex::Regex;

use crate::file::lookup::LookupResult;
use crate::file::zone::{self, Zone};
use crate::file::{self, SharedZones};
use crate::metrics::ZoneNames;

const MAX_REGEXP_LEN: usize = 10000;

/// Where and how zones are found (`loader`).
#[derive(Debug, Clone)]
pub struct Loader {
    pub directory: PathBuf,
    /// The origin template in `regexp.Expand` syntax (`${1}`).
    pub template: String,
    pub re: Regex,
    pub reload_interval: Duration,
}

impl Default for Loader {
    fn default() -> Self {
        Self {
            directory: PathBuf::new(),
            template: "${1}".into(),
            re: Regex::new(r"db\.(.*)").expect("valid"),
            reload_interval: Duration::from_secs(60),
        }
    }
}

/// The zones and loader of one `auto` directive (`Auto` minus `Next`).
pub struct Auto {
    pub loader: Loader,
    /// The loaded zones, by origin.
    pub zones: SharedZones,
    /// Zones from the directive or the server block.
    pub origins: Vec<String>,
    /// Transfer sources and NOTIFYs of the block.
    pub registry: Option<TransferRegistry>,
    /// The block's `prometheus` zone labels.
    pub metrics: Option<ZoneNames>,
    /// Serializes walks (startup and the reload ticker).
    walking: Mutex<()>,
}

impl Auto {
    pub fn new(loader: Loader, origins: Vec<String>) -> Self {
        Self {
            loader,
            zones: file::shared(file::Zones::default()),
            origins,
            registry: None,
            metrics: None,
            walking: Mutex::new(()),
        }
    }

    /// Origins of the loaded zones.
    pub fn names(&self) -> Vec<String> {
        self.zones.load().names.clone()
    }

    /// The zone with origin `name`.
    pub fn zone(&self, name: &str) -> Option<Arc<Zone>> {
        self.zones.load().z.get(name).cloned()
    }

    /// Scan the directory: load zones for new files, point existing zones
    /// at their (possibly moved) file and drop zones whose file is gone,
    /// like `Auto.Walk`. Returns the warnings it logged.
    pub fn walk(&self) -> Vec<String> {
        let _guard = self.walking.lock().unwrap_or_else(|e| e.into_inner());
        let mut warnings: Vec<String> = Vec::new();
        let mut warn = |msg: String| {
            kerndns_core::warning!(plugin = "auto", "{msg}");
            warnings.push(msg);
        };

        // filepath.Walk doesn't enter a symlinked root (a ConfigMap mount)
        let dir = eval_symlinks(&self.loader.directory);

        let mut zs = (**self.zones.load()).clone();
        let mut to_delete: HashMap<String, bool> = zs.names.iter().map(|n| (n.clone(), true)).collect();
        let mut seen: HashMap<String, PathBuf> = HashMap::new();
        let mut added: Vec<Arc<Zone>> = Vec::new();

        go_walk(&dir, &mut |path, is_dir, err| {
            if let Some(e) = err {
                warn(format!("error reading {}: {e}", path.display()));
            }
            let Some(is_dir) = is_dir else { return };
            if is_dir {
                return;
            }
            let Some(base) = path.file_name().and_then(|n| n.to_str()) else {
                return;
            };
            let Some(origin) = matches(&self.loader.re, base, &self.loader.template) else {
                return;
            };

            let clean = path.to_path_buf();
            if let Some(previous) = seen.get(&origin)
                && *previous != clean
            {
                warn(format!(
                    "Multiple zone files match origin {origin:?}: using {:?} instead of {:?}",
                    previous.display().to_string(),
                    clean.display().to_string()
                ));
                to_delete.insert(origin, false);
                return;
            }
            seen.insert(origin.clone(), clean.clone());

            if let Some(z) = zs.z.get(&origin) {
                to_delete.insert(origin, false);
                z.set_file(clean);
                return;
            }

            let text = match std::fs::read_to_string(&clean) {
                Ok(t) => t,
                Err(e) => {
                    warn(format!(
                        "Opening {} failed: {}",
                        path.display(),
                        go_err("open", path, &e)
                    ));
                    return;
                }
            };
            let name = match Name::from_ascii(&origin) {
                Ok(n) => n,
                Err(e) => {
                    warn(format!("Parse zone `{origin}': {e}"));
                    return;
                }
            };
            // serial 0: a new zone
            let data = match zone::parse(&text, &name, path, 0) {
                Ok(d) => d,
                Err(e) => {
                    warn(format!("Parse zone `{origin}': {e}"));
                    return;
                }
            };
            let mut z = Zone::new(name, path.to_path_buf(), data);
            z.reload_interval = self.loader.reload_interval;
            z.registry = self.registry.clone();
            let z = Arc::new(z);
            zs.z.insert(origin.clone(), z.clone());
            zs.names.push(origin.clone());
            added.push(z);
            if let Some(m) = &self.metrics {
                m.add(&origin);
            }
            kerndns_core::info!(plugin = "auto", "Inserting zone `{origin}' from: {}", path.display());
            to_delete.insert(origin, false);
        });

        for (origin, delete) in to_delete {
            if !delete {
                continue;
            }
            if let Some(m) = &self.metrics {
                m.remove(&origin);
            }
            if let Some(z) = zs.z.remove(&origin) {
                z.stop_reload();
            }
            zs.names.retain(|n| *n != origin);
            kerndns_core::info!(plugin = "auto", "Deleting zone `{origin}'");
        }
        self.zones.store(Arc::new(zs));

        // the zones' own reload loops (`Zones.Add` -> `Zone.Reload`)
        if tokio::runtime::Handle::try_current().is_ok() {
            for z in added {
                z.start_reload();
            }
        }
        warnings
    }

    /// Send NOTIFYs for every zone (`Auto.Notify`); a no-op without
    /// `transfer`.
    pub fn notify(&self) {
        if let Some(r) = &self.registry {
            for origin in self.names() {
                r.notify(&origin);
            }
        }
    }

    fn shutdown(&self) {
        for z in self.zones.load().z.values() {
            z.stop_reload();
        }
    }
}

/// `filepath.EvalSymlinks`: the directory with symlinks resolved, or as
/// given if that fails. A path without symlinks is kept as written.
fn eval_symlinks(dir: &Path) -> PathBuf {
    let Ok(resolved) = std::fs::canonicalize(dir) else {
        return dir.to_path_buf();
    };
    let absolute = if dir.is_absolute() {
        Some(dir.to_path_buf())
    } else {
        std::env::current_dir().ok().map(|c| c.join(dir))
    };
    match absolute {
        Some(a) if clean(&a) == resolved => dir.to_path_buf(),
        _ => resolved,
    }
}

/// Lexical `filepath.Clean` (enough to compare with a canonical path).
fn clean(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

/// Go's `*PathError` text, e.g. `lstat /x: no such file or directory`.
fn go_err(op: &str, path: &Path, e: &std::io::Error) -> String {
    let msg = match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        _ => e.to_string(),
    };
    format!("{op} {}: {msg}", path.display())
}

/// The callback of [`go_walk`]: path, whether it is a directory (`None` if
/// it could not be read) and the error reading it.
type WalkFn<'a> = dyn FnMut(&Path, Option<bool>, Option<String>) + 'a;

/// `filepath.Walk`: `f(path, is_dir, error)` for `root` and everything
/// below it in lexical order, without following symlinks to directories.
/// `is_dir` is `None` when the entry could not be read.
fn go_walk(root: &Path, f: &mut WalkFn<'_>) {
    match std::fs::symlink_metadata(root) {
        Err(e) => f(root, None, Some(go_err("lstat", root, &e))),
        Ok(m) => walk_one(root, m.is_dir(), f),
    }
}

fn walk_one(path: &Path, is_dir: bool, f: &mut WalkFn<'_>) {
    if !is_dir {
        f(path, Some(false), None);
        return;
    }
    let names = std::fs::read_dir(path).map(|rd| {
        let mut v: Vec<std::ffi::OsString> = rd.filter_map(|e| e.ok()).map(|e| e.file_name()).collect();
        v.sort();
        v
    });
    match names {
        Err(e) => {
            f(path, Some(true), Some(go_err("open", path, &e)));
        }
        Ok(names) => {
            f(path, Some(true), None);
            for n in names {
                let p = path.join(n);
                match std::fs::symlink_metadata(&p) {
                    Err(e) => f(&p, None, Some(go_err("lstat", &p, &e))),
                    Ok(m) => walk_one(&p, m.is_dir(), f),
                }
            }
        }
    }
}

/// Match `re` against the file name; on a match, expand `template` with
/// its submatches into a fully qualified origin (`matches`).
pub fn matches(re: &Regex, filename: &str, template: &str) -> Option<String> {
    let base = Path::new(filename)
        .file_name()
        .and_then(|b| b.to_str())
        .unwrap_or(filename);
    let caps = re.captures(base)?;
    let mut by = String::new();
    caps.expand(template, &mut by);
    if by.is_empty() {
        return None;
    }
    Some(fqdn(by))
}

/// `dns.Fqdn`.
fn fqdn(mut s: String) -> String {
    if !is_fqdn(&s) {
        s.push('.');
    }
    s
}

fn is_fqdn(s: &str) -> bool {
    let Some(rest) = s.strip_suffix('.') else {
        return false;
    };
    // an escaped final dot doesn't count
    let backslashes = rest.bytes().rev().take_while(|b| *b == b'\\').count();
    backslashes % 2 == 0
}

/// Rewrite the origin template for `Captures::expand`: every `{` gets a
/// `$` prefix, so `{1}` becomes `${1}` (`rewriteToExpand`).
pub fn rewrite_to_expand(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '{' {
            out.push('$');
        }
        out.push(c);
    }
    out
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "auto"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let (loader, origins) = auto_parse(c)?;
        let registry = TransferRegistry::of(c.config);
        let mut a = Auto::new(loader, origins);
        a.registry = Some(registry.clone());
        a.metrics = Some(ZoneNames::of(c.config));
        let a = Arc::new(a);
        registry.add_source(Arc::new(AutoTransfer(a.clone())));

        let ticker: Arc<Mutex<Option<tokio::task::AbortHandle>>> = Arc::default();
        let (a2, t2) = (a.clone(), ticker.clone());
        c.on_startup(move || {
            a2.walk();
            a2.notify();
            let interval = a2.loader.reload_interval;
            if interval.is_zero() {
                return Ok(());
            }
            let w = Arc::downgrade(&a2);
            let task = tokio::spawn(async move {
                let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tick.tick().await;
                    let Some(a) = w.upgrade() else { return };
                    let a2 = a.clone();
                    let _ = tokio::task::spawn_blocking(move || a2.walk()).await;
                    a.notify();
                }
            });
            *t2.lock().unwrap() = Some(task.abort_handle());
            Ok(())
        });
        let a3 = a.clone();
        c.on_shutdown(move || {
            if let Some(t) = ticker.lock().unwrap().take() {
                t.abort();
            }
            a3.shutdown();
        });

        c.add_plugin(move |next| Arc::new(AutoHandler { next, auto: a.clone() }));
        Ok(())
    }
}

/// `autoParse`: the loader settings and origins.
pub fn auto_parse(c: &mut Controller<'_>) -> Result<(Loader, Vec<String>), SetupError> {
    let mut l = Loader::default();
    let mut reload: Option<Duration> = None;
    let mut origins = Vec::new();
    let server_keys = c.server_block_keys();

    while c.next() {
        let args = c.remaining_args();
        origins = zones::origins_from_args_or_server_block(&args, &server_keys);

        while c.next_block() {
            match c.val() {
                // directory DIR [REGEXP TEMPLATE]
                "directory" => {
                    if !c.next_arg() {
                        return Err(c.arg_err());
                    }
                    l.directory = PathBuf::from(c.val());
                    if l.directory.is_relative()
                        && let Some(root) = &c.config.root
                    {
                        l.directory = root.join(&l.directory);
                    }
                    if let Err(e) = std::fs::metadata(&l.directory) {
                        if e.kind() != std::io::ErrorKind::NotFound {
                            let msg = format!(
                                "Unable to access root path '{}': {}",
                                l.directory.display(),
                                go_err("stat", &l.directory, &e)
                            );
                            return Err(c.errf(msg));
                        }
                        kerndns_core::warning!(plugin = "auto", "Directory does not exist: {}", l.directory.display());
                    }

                    if c.next_arg() {
                        if c.val().len() > MAX_REGEXP_LEN {
                            return Err(c.errf("regexp too large"));
                        }
                        l.re = Regex::new(c.val()).map_err(|e| SetupError::new("auto", regexp_error(&e)))?;
                        if l.re.captures_len() <= 1 {
                            return Err(c.errf("Need at least one sub expression"));
                        }
                        if !c.next_arg() {
                            return Err(c.arg_err());
                        }
                        l.template = rewrite_to_expand(c.val());
                    }

                    if c.next_arg() {
                        return Err(c.arg_err());
                    }
                }
                "reload" => {
                    let t = c.remaining_args();
                    let Some(d) = t.first() else {
                        return Err(SetupError::new("auto", "reload duration value is expected"));
                    };
                    let d = parse_reload(d).map_err(|e| SetupError::new("auto", format!("plugin/file: {e}")))?;
                    reload = Some(d);
                }
                "upstream" => {
                    // remove soon
                    c.remaining_args();
                }
                other => {
                    let msg = format!("unknown property '{other}'");
                    return Err(c.errf(msg));
                }
            }
        }
    }
    l.reload_interval = reload.unwrap_or(Duration::from_secs(60));
    Ok((l, origins))
}

/// `time.ParseDuration` plus auto's "negative is invalid" check.
fn parse_reload(s: &str) -> Result<Duration, String> {
    match parse_duration(s) {
        Ok(d) => Ok(d),
        Err(e) => match s.strip_prefix('-').map(parse_duration) {
            Some(Ok(d)) if d.is_zero() => Ok(d),
            Some(Ok(_)) => Err("invalid duration".into()),
            _ => Err(e),
        },
    }
}

/// A regex error on one line, in the style of Go's `error parsing regexp: ...`.
fn regexp_error(e: &regex::Error) -> String {
    let s = e.to_string();
    let detail = s
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix("error: "))
        .unwrap_or(s.trim());
    format!("error parsing regexp: {detail}")
}

/// `auto` as a zone source for `transfer` (`Auto.Transfer`).
struct AutoTransfer(Arc<Auto>);

impl Transferer for AutoTransfer {
    fn transfer(&self, zone: &str, serial: u32) -> Result<Vec<Vec<kerndns_core::proto::rr::Record>>, TransferError> {
        let z = self.0.zone(zone).ok_or(TransferError::NotAuthoritative)?;
        z.transfer(serial).map_err(TransferError::Other)
    }
}

/// The handler.
pub struct AutoHandler {
    pub next: Next,
    pub auto: Arc<Auto>,
}

/// The longest loaded zone containing `qname`; zone names from file names
/// may have upper case, which `dns.IsSubDomain` ignores.
fn match_zone<'a>(names: &'a [String], qname: &str) -> Option<&'a str> {
    names
        .iter()
        .filter(|z| zones::is_subdomain(&z.to_ascii_lowercase(), qname))
        .max_by_key(|z| z.len())
        .map(String::as_str)
}

#[async_trait]
impl Handler for AutoHandler {
    fn name(&self) -> &'static str {
        "auto"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let qname = req.name();

        // precheck with the origins: are we allowed to look here?
        if !self.auto.origins.iter().any(|o| zones::is_subdomain(o, &qname)) {
            return next_or_failure("auto", &self.next, ctx, w, req).await;
        }

        // now the real zone
        let z = {
            let zs = self.auto.zones.load();
            let Some(zone) = match_zone(&zs.names, &qname) else {
                // auto is authoritative: REFUSED rather than SERVFAIL
                if self.next.is_none() {
                    return Ok(ResponseCode::Refused);
                }
                return next_or_failure("auto", &self.next, ctx, w, req).await;
            };
            zs.z.get(zone).cloned()
        };
        let Some(z) = z else {
            return Ok(ResponseCode::ServFail);
        };

        // without transfer these reach us: no transfer allowed
        if matches!(req.qtype(), RecordType::AXFR | RecordType::IXFR) {
            return Ok(ResponseCode::Refused);
        }

        let name = req.qname().to_lowercase();
        let (answer, ns, extra, result) = z.lookup(ctx, req, &name).await;

        let mut m = req.reply();
        m.metadata.authoritative = true;
        m.answers = answer;
        m.authorities = ns;
        m.additionals = extra;

        match result {
            LookupResult::Success | LookupResult::NoData => {}
            LookupResult::NameError => m.metadata.response_code = ResponseCode::NXDomain,
            LookupResult::Delegation => m.metadata.authoritative = false,
            LookupResult::ServerFailure => {
                // a CNAME whose external target failed: send the CNAME
                if m.answers.is_empty() {
                    return Ok(ResponseCode::ServFail);
                }
                m.metadata.response_code = ResponseCode::ServFail;
            }
        }

        w.write_msg(m)
            .await
            .map_err(|e| PluginError::servfail("auto", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::zone::ZoneData;
    use crate::testutil::*;

    const ZONE_CONTENT: &str = "; testzone
@	IN	SOA	sns.dns.icann.org. noc.dns.icann.org. 2016082534 7200 3600 1209600 3600
		NS	a.iana-servers.net.
		NS	b.iana-servers.net.

www IN A 127.0.0.1
";

    /// A directory removed on drop (`t.TempDir()`).
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("kerndns-auto-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn auto_for(dir: &Path, re: &str) -> Auto {
        Auto::new(
            Loader {
                directory: dir.to_path_buf(),
                re: Regex::new(re).unwrap(),
                template: "${1}".into(),
                reload_interval: Duration::ZERO,
            },
            Vec::new(),
        )
    }

    /// `createFiles`: db.example.org, aa.example.org and two symlinks to the first.
    fn create_files() -> TempDir {
        let t = TempDir::new();
        for name in ["db.example.org", "aa.example.org"] {
            std::fs::write(t.path().join(name), ZONE_CONTENT).unwrap();
        }
        std::os::unix::fs::symlink(t.path().join("db.example.org"), t.path().join("db.example.com")).unwrap();
        std::os::unix::fs::symlink(t.path().join("db.example.org"), t.path().join("aa.example.com")).unwrap();
        t
    }

    // setup_test.go: TestAutoParse
    #[test]
    fn auto_parse_table() {
        let tests: &[(&str, bool, &str, &str, &str, Duration)] = &[
            (
                "auto example.org {\n directory /tmp\n}",
                false,
                "/tmp",
                "${1}",
                r"db\.(.*)",
                Duration::from_secs(60),
            ),
            (
                "auto 10.0.0.0/24 {\n directory /tmp\n}",
                false,
                "/tmp",
                "${1}",
                r"db\.(.*)",
                Duration::from_secs(60),
            ),
            (
                "auto {\n directory /tmp\n reload 0\n}",
                false,
                "/tmp",
                "${1}",
                r"db\.(.*)",
                Duration::ZERO,
            ),
            (
                "auto {\n directory /tmp (.*) bliep\n}",
                false,
                "/tmp",
                "bliep",
                "(.*)",
                Duration::from_secs(60),
            ),
            (
                "auto {\n directory /tmp (.*) bliep\n reload 10s\n}",
                false,
                "/tmp",
                "bliep",
                "(.*)",
                Duration::from_secs(10),
            ),
            // NO_RELOAD has been deprecated.
            (
                "auto {\n directory /tmp\n no_reload\n}",
                true,
                "",
                "",
                "",
                Duration::ZERO,
            ),
            // TIMEOUT has been deprecated.
            (
                "auto {\n directory /tmp (.*) bliep 10\n}",
                true,
                "",
                "",
                "",
                Duration::ZERO,
            ),
            // TRANSFER has been deprecated.
            (
                "auto {\n directory /tmp (.*) bliep 10\n transfer to 127.0.0.1\n}",
                true,
                "",
                "",
                "",
                Duration::ZERO,
            ),
            // no template specified.
            ("auto {\n directory /tmp (.*)\n}", true, "", "", "", Duration::ZERO),
            // no directory specified.
            ("auto example.org {\n directory\n}", true, "", "", "", Duration::ZERO),
            // illegal REGEXP.
            (
                "auto example.org {\n directory /tmp * {1}\n}",
                true,
                "",
                "",
                "",
                Duration::ZERO,
            ),
            // non-existent directory.
            (
                "auto example.org {\n directory /foobar/coredns * {1}\n}",
                true,
                "",
                "",
                "",
                Duration::ZERO,
            ),
            // unexpected argument.
            (
                "auto example.org {\n directory /tmp (.*) {1} aa\n}",
                true,
                "",
                "",
                "",
                Duration::ZERO,
            ),
            // upstream directive should not error and should consume args
            (
                "auto example.org {\n directory /tmp\n upstream 8.8.8.8 1.1.1.1\n}",
                false,
                "/tmp",
                "${1}",
                r"db\.(.*)",
                Duration::from_secs(60),
            ),
            // upstream directive with no args should not error
            (
                "auto example.org {\n directory /tmp\n upstream\n}",
                false,
                "/tmp",
                "${1}",
                r"db\.(.*)",
                Duration::from_secs(60),
            ),
        ];
        for (i, (input, should_err, dir, templ, re, reload)) in tests.iter().enumerate() {
            let res = with_controller("auto", input, auto_parse);
            match res {
                Err(e) => assert!(*should_err, "test {i}: unexpected error {e}"),
                Ok((l, _)) => {
                    assert!(!should_err, "test {i}: expected an error");
                    assert_eq!(l.directory, PathBuf::from(dir), "test {i}");
                    assert_eq!(l.template, *templ, "test {i}");
                    assert_eq!(l.re.as_str(), *re, "test {i}");
                    assert_eq!(l.reload_interval, *reload, "test {i}");
                }
            }
        }
    }

    #[test]
    fn auto_parse_origins_and_errors() {
        let (_, origins) =
            with_controller("auto", "auto example.org 10.0.0.0/24 {\n directory /tmp\n}", auto_parse).unwrap();
        assert_eq!(origins, ["example.org.", "0.0.10.in-addr.arpa."]);
        let (_, origins) = with_controller("auto", "auto {\n directory /tmp\n}", auto_parse).unwrap();
        assert_eq!(origins, ["."]);

        let err = |s: &str| with_controller("auto", s, auto_parse).unwrap_err().to_string();
        assert_eq!(
            err("auto {\n directory /tmp\n no_reload\n}"),
            "plugin/auto: Corefile:4 - Error during parsing: unknown property 'no_reload'"
        );
        assert_eq!(
            err("auto {\n directory /tmp (.*)\n}"),
            "plugin/auto: Corefile:3 - Error during parsing: Wrong argument count or unexpected line ending after '(.*)'"
        );
        assert_eq!(
            err("auto {\n directory /tmp db\\..*\n}"),
            "plugin/auto: Corefile:3 - Error during parsing: Need at least one sub expression"
        );
        assert!(err("auto {\n directory /tmp * {1}\n}").starts_with("plugin/auto: error parsing regexp: "));
    }

    // setup_test.go: TestSetupReload
    #[test]
    fn setup_reload() {
        let tests = [
            ("reload valid", "auto {\n directory .\n reload 5s\n}", false),
            ("reload disable", "auto {\n directory .\n reload 0\n}", false),
            ("reload invalid", "auto {\n directory .\n reload -1s\n}", true),
            ("reload invalid", "auto {\n directory .\n reload\n}", true),
        ];
        for (name, config, want_err) in tests {
            assert_eq!(!setup_ok(&Setup, config), want_err, "{name}");
        }
        assert_eq!(
            setup_err(&Setup, "auto {\n directory .\n reload -1s\n}"),
            "plugin/auto: plugin/file: invalid duration"
        );
        assert_eq!(
            setup_err(&Setup, "auto {\n directory .\n reload\n}"),
            "plugin/auto: reload duration value is expected"
        );
    }

    // setup_test.go: TestAutoParseLargeRegex
    #[test]
    fn auto_parse_large_regex() {
        let large = "a".repeat(MAX_REGEXP_LEN + 1);
        let err = setup_err(&Setup, &format!("auto {{\n directory /tmp {large} {{1}}\n}}"));
        assert!(err.contains("regexp too large"), "{err}");
    }

    // regexp_test.go: TestRewriteToExpand
    #[test]
    fn rewrite_to_expand_table() {
        for (input, want) in [("", ""), ("{1}", "${1}"), ("{1", "${1")] {
            assert_eq!(rewrite_to_expand(input), want);
        }
    }

    #[test]
    fn matches_expands_template() {
        let re = Regex::new(r"db\.(.*)").unwrap();
        assert_eq!(matches(&re, "db.example.org", "${1}").as_deref(), Some("example.org."));
        assert_eq!(
            matches(&re, "/x/y/db.example.org", "${1}").as_deref(),
            Some("example.org.")
        );
        assert_eq!(matches(&re, "aa.example.org", "${1}"), None);
        let re = Regex::new(r"www\.db\.(.*)").unwrap();
        assert_eq!(
            matches(&re, "www.db.example.org", &rewrite_to_expand("{1}")).as_deref(),
            Some("example.org.")
        );
        let re = Regex::new(r"(.*)\.(.*)").unwrap();
        assert_eq!(
            matches(&re, "a.b", &rewrite_to_expand("{2}.{1}")).as_deref(),
            Some("b.a.")
        );
        // an empty expansion is no match
        assert_eq!(matches(&re, "a.b", "$9"), None);
    }

    // walk_test.go: TestWalk
    #[test]
    fn walk() {
        let t = create_files();
        let a = auto_for(t.path(), r"db\.(.*)");
        a.walk();
        for name in ["example.com.", "example.org."] {
            assert!(a.zone(name).is_some(), "{name} should have been added");
        }
    }

    // walk_test.go: TestWalkSOAOrigin
    #[test]
    fn walk_soa_origin() {
        let t = TempDir::new();
        let path = t.path().join("db.example.org");
        std::fs::write(&path, ZONE_CONTENT.replacen('@', "example.net.", 1)).unwrap();
        let a = auto_for(t.path(), r"^db\.(.*)$");
        a.walk();
        assert!(a.names().is_empty(), "loaded a zone with a mismatched SOA owner");

        std::fs::write(&path, ZONE_CONTENT).unwrap();
        a.walk();
        let z = a.zone("example.org.").expect("did not load the corrected zone");
        let soa = z.snapshot().apex.soa.clone().expect("SOA");
        assert_eq!(soa.name.to_ascii(), "example.org.");
    }

    // walk_test.go: TestWalkSymlinkedDirectory
    #[test]
    fn walk_symlinked_directory() {
        let t = create_files();
        let other = TempDir::new();
        let link = other.path().join("zones");
        std::os::unix::fs::symlink(t.path(), &link).unwrap();
        let a = auto_for(&link, r"db\.(.*)");
        a.walk();
        for name in ["example.com.", "example.org."] {
            assert!(
                a.zone(name).is_some(),
                "{name} should have been added when directory is a symlink"
            );
        }
    }

    // walk_test.go: TestWalkNonExistent
    #[test]
    fn walk_non_existent() {
        let a = auto_for(Path::new("highly_unlikely_to_exist_dir"), r"db\.(.*)");
        let w = a.walk();
        assert_eq!(
            w,
            [
                "error reading highly_unlikely_to_exist_dir: lstat highly_unlikely_to_exist_dir: no such file or directory"
            ]
        );
        assert!(a.names().is_empty());
    }

    // walk_test.go: TestWalkWarnsForDuplicateOrigin
    #[test]
    fn walk_warns_for_duplicate_origin() {
        let t = TempDir::new();
        let zone = t.path().join("example.org.zone");
        let backup = t.path().join("example.org.zone.bak-20260528");
        for p in [&zone, &backup] {
            std::fs::write(p, ZONE_CONTENT).unwrap();
        }
        let a = auto_for(t.path(), r"(.*)\.zone");
        let w = a.walk();
        let dup: Vec<&String> = w
            .iter()
            .filter(|m| m.starts_with("Multiple zone files match origin \"example.org.\""))
            .collect();
        assert_eq!(dup.len(), 1, "{w:?}");
        // the kept (first, live) file is in the "using" slot
        assert!(dup[0].contains("example.org.zone\" instead of \""), "{}", dup[0]);
        assert!(dup[0].contains("example.org.zone.bak-20260528"), "{}", dup[0]);

        let w = a.walk();
        let n = w
            .iter()
            .filter(|m| m.starts_with("Multiple zone files match origin \"example.org.\""))
            .count();
        assert_eq!(n, 1, "after reload: {w:?}");
    }

    // walk_test.go: TestWalkKeepsFirstMatchingFileForOrigin
    #[test]
    fn walk_keeps_first_matching_file_for_origin() {
        let t = TempDir::new();
        let dir = std::fs::canonicalize(t.path()).unwrap();
        let zone = dir.join("example.org.zone");
        let backup = dir.join("example.org.zone.bak-20260528");
        for p in [&zone, &backup] {
            std::fs::write(p, ZONE_CONTENT).unwrap();
        }
        let a = auto_for(&dir, r"(.*)\.zone");
        a.walk();
        assert_eq!(a.zone("example.org.").unwrap().file(), zone);
        a.walk();
        assert_eq!(a.zone("example.org.").unwrap().file(), zone, "after reload");
    }

    // watcher_test.go: TestWatcher
    #[test]
    fn watcher() {
        let t = create_files();
        let a = auto_for(t.path(), r"db\.(.*)");
        a.walk();
        // 3 apex records and 1 "real" one; only the latter is in the tree
        for name in ["example.org.", "example.com."] {
            let n: usize = a
                .zone(name)
                .unwrap()
                .snapshot()
                .tree
                .elems()
                .map(|e| e.all().count())
                .sum();
            assert_eq!(n, 1, "{name}");
        }

        std::fs::remove_file(t.path().join("db.example.com")).unwrap();
        a.walk();
        assert!(a.zone("example.com.").is_none(), "expected example.com. to be gone");
        assert!(
            a.zone("example.org.").is_some(),
            "expected example.org. to still be there"
        );
        assert_eq!(a.names(), ["example.org."]);
    }

    // watcher_test.go: TestSymlinks
    #[test]
    fn symlinks() {
        let t = create_files();
        let dir = std::fs::canonicalize(t.path()).unwrap();
        let a = auto_for(&dir, r"db\.(.*)");
        a.walk();

        // repoint the zone at a file in a subdirectory
        std::fs::remove_file(dir.join("db.example.com")).unwrap();
        let data = dir.join("..data");
        std::fs::create_dir(&data).unwrap();
        let new_file = data.join("db.example.com");
        std::os::unix::fs::symlink(dir.join("db.example.org"), &new_file).unwrap();
        a.walk();

        let z = a.zone("example.com.").expect("example.com. is still loaded");
        assert_eq!(z.file(), new_file);
    }

    fn auto_with(origins: &[&str], names: &[&str], zone: Option<ZoneData>) -> AutoHandler {
        let a = Auto::new(Loader::default(), origins.iter().map(|s| s.to_string()).collect());
        let mut zs = file::Zones::default();
        for n in names {
            zs.names.push(n.to_string());
            if let Some(d) = &zone {
                zs.z.insert(
                    n.to_string(),
                    Arc::new(Zone::new(Name::from_ascii(n).unwrap(), PathBuf::new(), d.clone())),
                );
            }
        }
        a.zones.store(Arc::new(zs));
        AutoHandler {
            next: None,
            auto: Arc::new(a),
        }
    }

    #[test]
    fn auto_name() {
        assert_eq!(auto_with(&[], &[], None).name(), "auto");
    }

    // auto_test.go: TestAutoServeDNS
    #[tokio::test]
    async fn auto_serve_dns() {
        let tests = [
            // zone exists but has no data
            (
                "valid A query",
                "test.example.org.",
                RecordType::A,
                Some(ResponseCode::ServFail),
            ),
            (
                "AXFR query refused",
                "test.example.org.",
                RecordType::AXFR,
                Some(ResponseCode::Refused),
            ),
            (
                "IXFR query refused",
                "test.example.org.",
                RecordType::IXFR,
                Some(ResponseCode::Refused),
            ),
            ("no matching zone", "test.notfound.org.", RecordType::A, None),
        ];
        for (name, qname, qtype, want) in tests {
            let a = auto_with(&["example.org."], &["example.org."], Some(ZoneData::default()));
            let (res, _) = serve(&a, &query(qname, qtype, "10.0.0.1:53")).await;
            match want {
                Some(code) => assert_eq!(res.unwrap(), code, "{name}"),
                None => assert!(res.is_err(), "{name}: expected an error for a non-matching zone"),
            }
        }
    }

    // auto_test.go: TestAutoServeDNSZoneMatching
    #[tokio::test]
    async fn auto_serve_dns_zone_matching() {
        // (name, origins, names, qname, has_zone, should_refuse)
        let tests = [
            (
                "exact zone match",
                "example.org.",
                "example.org.",
                "test.example.org.",
                true,
                false,
            ),
            (
                "subdomain zone match",
                "example.org.",
                "example.org.",
                "sub.test.example.org.",
                true,
                false,
            ),
            (
                "no origin match",
                "other.org.",
                "example.org.",
                "test.example.org.",
                false,
                false,
            ),
            (
                "origin match but no name match",
                "example.org.",
                "other.org.",
                "test.example.org.",
                false,
                true,
            ),
        ];
        for (name, origin, zone, qname, has_zone, should_refuse) in tests {
            let a = auto_with(&[origin], &[zone], Some(ZoneData::default()));
            let (res, _) = serve(&a, &query(qname, RecordType::A, "10.0.0.1:53")).await;
            if has_zone {
                assert!(res.is_ok(), "{name}");
            } else if should_refuse {
                assert_eq!(res.unwrap(), ResponseCode::Refused, "{name}");
            } else {
                assert!(res.is_err(), "{name}");
            }
        }
    }

    // auto_test.go: TestAutoServeDNSNilZone / TestAutoServeDNSMissingZone
    #[tokio::test]
    async fn auto_serve_dns_missing_zone() {
        let a = auto_with(&["example.org."], &["example.org."], None);
        let (res, _) = serve(&a, &query("test.example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(res.unwrap(), ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn auto_serves_loaded_zone() {
        let t = create_files();
        let a = auto_for(t.path(), r"db\.(.*)");
        a.walk();
        let a = Auto {
            origins: vec!["org.".into()],
            ..a
        };
        let h = AutoHandler {
            next: None,
            auto: Arc::new(a),
        };
        let (res, w) = serve(&h, &query("www.example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(res.unwrap(), ResponseCode::NoError);
        let m = w.msg().expect("answer written");
        assert!(m.metadata.authoritative);
        assert_eq!(m.answers.len(), 1);
        let (_, w) = serve(&h, &query("nope.example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(w.msg().unwrap().metadata.response_code, ResponseCode::NXDomain);
        // origins limit what is answered even if more zones are loaded
        let (res, _) = serve(&h, &query("www.example.com.", RecordType::A, "10.0.0.1:53")).await;
        assert!(res.is_err());
    }

    // xfr_test.go: TestAutoNotify
    #[test]
    fn auto_notify_without_transfer() {
        let a = auto_with(&[], &["example.org.", "test.org."], None);
        a.auto.notify();
    }

    // xfr_test.go: TestAutoTransferZoneCase
    #[test]
    fn auto_transfer_zone_case() {
        let a = auto_with(&[], &["example.org."], Some(ZoneData::default()));
        let t = AutoTransfer(a.auto.clone());
        assert_eq!(
            t.transfer("example.org.", 1234),
            Err(TransferError::Other("no SOA".into()))
        );
        assert_eq!(t.transfer("EXAMPLE.ORG.", 1234), Err(TransferError::NotAuthoritative));
        assert_eq!(t.transfer("other.org.", 1234), Err(TransferError::NotAuthoritative));
    }

    #[test]
    fn auto_transfer_loaded_zone() {
        let t = create_files();
        let a = auto_for(t.path(), r"db\.(.*)");
        a.walk();
        let x = AutoTransfer(Arc::new(a));
        let n: usize = x.transfer("example.org.", 0).unwrap().iter().map(Vec::len).sum();
        assert_eq!(n, 5);
    }

    #[test]
    fn metrics_zone_names_follow_walks() {
        let t = create_files();
        let mut a = auto_for(t.path(), r"db\.(.*)");
        let m = ZoneNames::default();
        a.metrics = Some(m.clone());
        a.walk();
        let mut names = (*m.names()).clone();
        names.sort();
        assert_eq!(names, ["example.com.", "example.org."]);
        std::fs::remove_file(t.path().join("db.example.com")).unwrap();
        a.walk();
        assert_eq!(*m.names(), ["example.org."]);
    }
}
