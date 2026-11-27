//! `hosts`: answers from an /etc/hosts-style file and inline entries.
//! Port of `plugin/hosts`.
//!
//! ```text
//! hosts [FILE [ZONES...]] {
//!     [INLINE]
//!     ttl SECONDS
//!     no_reverse
//!     reload DURATION
//!     fallthrough [ZONES...]
//!     fallthrough_unsupported
//! }
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use kerndns_core::duration::parse_duration;
use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::rdata::{A, AAAA, PTR};
use kerndns_core::proto::rr::{Name, RData, Record, RecordType};
use kerndns_core::zones::{self, Fall, extract_address_from_reverse, is_subdomain};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, next_or_failure,
};

const MAX_FIELD_SIZE: usize = 1024;

/// Parsed entries, like `hosts.Map`.
#[derive(Debug, Default, Clone)]
pub struct Map {
    name4: HashMap<String, Vec<IpAddr>>,
    name6: HashMap<String, Vec<IpAddr>>,
    wild4: HashMap<String, Vec<IpAddr>>,
    wild6: HashMap<String, Vec<IpAddr>>,
    addr: HashMap<String, Vec<String>>,
}

impl Map {
    pub fn len(&self) -> usize {
        [&self.name4, &self.name6, &self.wild4, &self.wild6]
            .iter()
            .flat_map(|m| m.values())
            .map(Vec::len)
            .sum::<usize>()
            + self.addr.values().map(Vec::len).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse an address field: a `%zone` suffix is dropped and IPv4-mapped
/// IPv6 addresses count as IPv4, like Go's `net.ParseIP` + `To4`.
fn parse_ip(s: &str) -> Option<IpAddr> {
    let s = s.split('%').next().unwrap_or(s);
    match s.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => Some(IpAddr::V4(v4)),
            None => Some(IpAddr::V6(v6)),
        },
        ip => Some(ip),
    }
}

fn normalize(name: &str) -> String {
    let mut n = name.to_ascii_lowercase();
    if !n.ends_with('.') {
        n.push('.');
    }
    n
}

/// Parse hosts-file text, like `Hostsfile.parseSource`.
pub fn parse_hosts(text: &str, origins: &[String], auto_reverse: bool, src: &str) -> Map {
    let mut m = Map::default();
    for (no, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_ascii_whitespace();
        let Some(addr_field) = fields.next() else { continue };
        if addr_field.len() > MAX_FIELD_SIZE {
            kerndns_core::error!(
                plugin = "hosts",
                "{src}, line {}: address longer than {MAX_FIELD_SIZE} bytes, dropping the line",
                no + 1
            );
            continue;
        }
        let Some(addr) = parse_ip(addr_field) else { continue };
        for field in fields {
            if field.len() > MAX_FIELD_SIZE {
                kerndns_core::error!(
                    plugin = "hosts",
                    "{src}, line {}: name longer than {MAX_FIELD_SIZE} bytes, dropping the name",
                    no + 1
                );
                continue;
            }
            let name = normalize(field);
            if !origins.iter().any(|o| is_subdomain(o, &name)) {
                continue;
            }
            let v4 = addr.is_ipv4();
            if name.starts_with("*.") {
                let map = if v4 { &mut m.wild4 } else { &mut m.wild6 };
                map.entry(name).or_default().push(addr);
                continue;
            }
            let map = if v4 { &mut m.name4 } else { &mut m.name6 };
            map.entry(name.clone()).or_default().push(addr);
            if auto_reverse {
                m.addr.entry(addr.to_string()).or_default().push(name);
            }
        }
    }
    m
}

/// `*.` + everything after the first label, `None` for a single label.
fn wildcard_of(name: &str) -> Option<String> {
    let i = name.find('.')?;
    let rest = &name[i + 1..];
    if rest.is_empty() {
        None
    } else {
        Some(format!("*.{rest}"))
    }
}

struct FileState {
    map: Map,
    mtime: Option<SystemTime>,
    size: u64,
}

/// The hosts data: the file (reloaded) and the inline entries (fixed).
pub struct Hostsfile {
    path: PathBuf,
    origins: Vec<String>,
    auto_reverse: bool,
    file: RwLock<FileState>,
    inline: Map,
}

impl Hostsfile {
    /// Re-read the file if its mtime or size changed, like `readHosts`.
    pub fn read_hosts(&self) {
        let Ok(meta) = std::fs::metadata(&self.path) else {
            return;
        };
        let (mtime, size) = (meta.modified().ok(), meta.len());
        {
            let st = self.file.read().unwrap();
            if st.mtime == mtime && st.size == size && mtime.is_some() {
                return;
            }
        }
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return;
        };
        let src = format!("Hosts file {:?}", self.path.display().to_string());
        let map = parse_hosts(&text, &self.origins, self.auto_reverse, &src);
        kerndns_core::debug!(plugin = "hosts", "Parsed hosts file into {} entries", map.len());
        let path = self.path.display().to_string();
        crate::pluginmetrics::HOSTS_ENTRIES
            .with_label_values(&[&path])
            .set((self.inline.len() + map.len()) as f64);
        if let Some(t) = mtime.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()) {
            crate::pluginmetrics::HOSTS_RELOAD_TIME
                .with_label_values(&[] as &[&str])
                .set(t.as_secs_f64());
        }
        *self.file.write().unwrap() = FileState { map, mtime, size };
    }

    fn lookup_in(m: &HashMap<String, Vec<IpAddr>>, wild: &HashMap<String, Vec<IpAddr>>, host: &str) -> Vec<IpAddr> {
        if let Some(ips) = m.get(host) {
            return ips.clone();
        }
        if let Some(p) = wildcard_of(host)
            && let Some(ips) = wild.get(&p)
        {
            return ips.clone();
        }
        Vec::new()
    }

    pub fn lookup_v4(&self, host: &str) -> Vec<IpAddr> {
        let host = host.to_ascii_lowercase();
        let st = self.file.read().unwrap();
        let mut v = Self::lookup_in(&st.map.name4, &st.map.wild4, &host);
        v.extend(Self::lookup_in(&self.inline.name4, &self.inline.wild4, &host));
        v
    }

    pub fn lookup_v6(&self, host: &str) -> Vec<IpAddr> {
        let host = host.to_ascii_lowercase();
        let st = self.file.read().unwrap();
        let mut v = Self::lookup_in(&st.map.name6, &st.map.wild6, &host);
        v.extend(Self::lookup_in(&self.inline.name6, &self.inline.wild6, &host));
        v
    }

    pub fn lookup_addr(&self, addr: IpAddr) -> Vec<String> {
        let key = parse_ip(&addr.to_string()).unwrap_or(addr).to_string();
        let st = self.file.read().unwrap();
        let mut v = st.map.addr.get(&key).cloned().unwrap_or_default();
        v.extend(self.inline.addr.get(&key).cloned().unwrap_or_default());
        v
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "hosts"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut path = PathBuf::from("/etc/hosts");
        let mut origins: Vec<String> = Vec::new();
        let mut fall = Fall::default();
        let mut fallthrough_unsupported = false;
        let mut auto_reverse = true;
        let mut ttl: u32 = 3600;
        let mut reload = Duration::from_secs(5);
        let mut inline: Vec<String> = Vec::new();
        let server_keys = c.server_block_keys();
        let mut seen = false;

        while c.next() {
            if seen {
                return Err(SetupError::new(
                    "hosts",
                    "this plugin can only be used once per Server Block",
                ));
            }
            seen = true;
            let mut args = c.remaining_args();
            if !args.is_empty() {
                path = PathBuf::from(args.remove(0));
                if path.is_relative()
                    && let Some(root) = &c.config.root
                {
                    path = root.join(&path);
                }
                match std::fs::metadata(&path) {
                    Ok(m) if m.is_dir() => {
                        kerndns_core::warning!(
                            plugin = "hosts",
                            "Hosts file {:?} is a directory",
                            path.display().to_string()
                        )
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        kerndns_core::warning!(plugin = "hosts", "File does not exist: {}", path.display())
                    }
                    Err(e) => {
                        let msg = format!("unable to access hosts file '{}': {e}", path.display());
                        return Err(c.errf(msg));
                    }
                }
            }
            origins = zones::origins_from_args_or_server_block(&args, &server_keys);

            while c.next_block() {
                match c.val() {
                    "fallthrough" => {
                        let a = c.remaining_args();
                        fall.set_zones_from_args(&a);
                    }
                    "fallthrough_unsupported" => {
                        if !c.remaining_args().is_empty() {
                            return Err(c.arg_err());
                        }
                        fallthrough_unsupported = true;
                    }
                    "no_reverse" => auto_reverse = false,
                    "ttl" => {
                        let r = c.remaining_args();
                        let Some(v) = r.first() else {
                            return Err(c.errf("ttl needs a time in second"));
                        };
                        let Ok(v) = v.parse::<i64>() else {
                            return Err(c.errf("ttl needs a number of second"));
                        };
                        if v <= 0 || v > 65535 {
                            return Err(c.errf("ttl provided is invalid"));
                        }
                        ttl = v as u32;
                    }
                    "reload" => {
                        let r = c.remaining_args();
                        if r.len() != 1 {
                            return Err(c.errf("reload needs a duration (zero seconds to disable)"));
                        }
                        reload = match parse_duration(&r[0]) {
                            Ok(d) => d,
                            Err(e) if e.contains("negative") => {
                                let msg = format!("invalid negative duration for reload '{}'", r[0]);
                                return Err(c.errf(msg));
                            }
                            Err(_) => {
                                let msg = format!("invalid duration for reload '{}'", r[0]);
                                return Err(c.errf(msg));
                            }
                        };
                    }
                    other => {
                        if fall.zones.is_empty() {
                            let mut line = vec![other.to_string()];
                            line.extend(c.remaining_args());
                            inline.push(line.join(" "));
                            continue;
                        }
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
        }
        if fallthrough_unsupported && fall.zones.is_empty() {
            return Err(c.errf("fallthrough_unsupported requires fallthrough"));
        }

        let inline_map = parse_hosts(&inline.join("\n"), &origins, auto_reverse, "Inline hosts entries");
        let hf = Arc::new(Hostsfile {
            path,
            origins: origins.clone(),
            auto_reverse,
            file: RwLock::new(FileState {
                map: Map::default(),
                mtime: None,
                size: 0,
            }),
            inline: inline_map,
        });

        let task: Arc<std::sync::Mutex<Option<tokio::task::AbortHandle>>> = Arc::default();
        {
            let hf = hf.clone();
            let task = task.clone();
            c.on_startup(move || {
                hf.read_hosts();
                if !reload.is_zero() {
                    let weak = Arc::downgrade(&hf);
                    let t = tokio::spawn(async move {
                        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + reload, reload);
                        loop {
                            tick.tick().await;
                            let Some(hf) = weak.upgrade() else { return };
                            hf.read_hosts();
                        }
                    });
                    *task.lock().unwrap() = Some(t.abort_handle());
                }
                Ok(())
            });
        }
        c.on_shutdown(move || {
            if let Some(t) = task.lock().unwrap().take() {
                t.abort();
            }
        });

        let fall = Arc::new(fall);
        let origins = Arc::new(origins);
        c.add_plugin(move |next| {
            Arc::new(Hosts {
                next,
                hf: hf.clone(),
                origins: origins.clone(),
                fall: fall.clone(),
                fallthrough_unsupported,
                ttl,
            })
        });
        Ok(())
    }
}

pub struct Hosts {
    next: Next,
    hf: Arc<Hostsfile>,
    origins: Arc<Vec<String>>,
    fall: Arc<Fall>,
    fallthrough_unsupported: bool,
    ttl: u32,
}

#[async_trait]
impl Handler for Hosts {
    fn name(&self) -> &'static str {
        "hosts"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let qname = req.name();
        let qtype = req.qtype();
        if !self.origins.iter().any(|o| is_subdomain(o, &qname)) && qtype != RecordType::PTR {
            return next_or_failure("hosts", &self.next, ctx, w, req).await;
        }
        let owner = || Name::from_ascii(&qname).unwrap_or_else(|_| req.qname().clone());
        let mk = |data: RData| Record::from_rdata(owner(), self.ttl, data);

        let answers: Vec<Record> = match qtype {
            RecordType::PTR => {
                let names = extract_address_from_reverse(&qname)
                    .map(|a| self.hf.lookup_addr(a))
                    .unwrap_or_default();
                if names.is_empty() {
                    return next_or_failure("hosts", &self.next, ctx, w, req).await;
                }
                names
                    .iter()
                    .filter_map(|n| Name::from_ascii(n).ok())
                    .map(|n| mk(RData::PTR(PTR(n))))
                    .collect()
            }
            RecordType::A => self
                .hf
                .lookup_v4(&qname)
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(mk(RData::A(A(v4)))),
                    _ => None,
                })
                .collect(),
            RecordType::AAAA => self
                .hf
                .lookup_v6(&qname)
                .into_iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(mk(RData::AAAA(AAAA(v6)))),
                    _ => None,
                })
                .collect(),
            _ => {
                if self.fallthrough_unsupported && self.fall.through(&qname) {
                    return next_or_failure("hosts", &self.next, ctx, w, req).await;
                }
                Vec::new()
            }
        };

        if answers.is_empty() && self.hf.lookup_v4(&qname).is_empty() && self.hf.lookup_v6(&qname).is_empty() {
            if self.fall.through(&qname) {
                return next_or_failure("hosts", &self.next, ctx, w, req).await;
            }
            return Ok(ResponseCode::ServFail);
        }

        let mut m = req.reply();
        m.metadata.authoritative = true;
        m.answers = answers;
        w.write_msg(m)
            .await
            .map_err(|e| PluginError::servfail("hosts", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    const HOSTS: &str = "127.0.0.1 localhost localhost.domain\n\
                         ::1 localhost # comment\n\
                         ::FFFF:10.0.0.5 mapped.example.org\n\
                         10.0.0.1 a.example.org A.Example.org\n\
                         10.0.0.2 *.wild.example.org\n\
                         fe80::1%lo0 linklocal.example.org\n\
                         bogus not-an-address\n";

    fn hf(text: &str) -> Hostsfile {
        let origins = vec![".".to_string()];
        Hostsfile {
            path: PathBuf::new(),
            origins: origins.clone(),
            auto_reverse: true,
            file: RwLock::new(FileState {
                map: parse_hosts(text, &origins, true, "test"),
                mtime: None,
                size: 0,
            }),
            inline: Map::default(),
        }
    }

    #[test]
    fn parsing() {
        let h = hf(HOSTS);
        assert_eq!(h.lookup_v4("localhost."), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(h.lookup_v6("localhost."), vec!["::1".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            h.lookup_v4("mapped.example.org."),
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(h.lookup_v4("a.example.org.").len(), 2);
        assert_eq!(h.lookup_v4("x.wild.example.org.").len(), 1);
        assert!(h.lookup_v4("x.y.wild.example.org.").is_empty());
        assert_eq!(h.lookup_v6("linklocal.example.org.").len(), 1);
        assert_eq!(
            h.lookup_addr("10.0.0.1".parse().unwrap()),
            vec!["a.example.org.", "a.example.org."]
        );
        assert!(h.lookup_v4("not-an-address.").is_empty());
    }

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "hosts"));
        assert!(setup_ok(
            &Setup,
            "hosts /etc/hosts example.org {\n 10.0.0.1 a.example.org\n ttl 60\n no_reverse\n reload 0\n}"
        ));
        assert!(setup_err(&Setup, "hosts {\n ttl 0\n}").contains("ttl provided is invalid"));
        assert!(setup_err(&Setup, "hosts {\n reload\n}").contains("reload needs a duration"));
        assert!(setup_err(&Setup, "hosts {\n fallthrough_unsupported\n}").contains("requires fallthrough"));
        assert!(setup_err(&Setup, "hosts {\n fallthrough\n foo\n}").contains("unknown property 'foo'"));
    }

    #[tokio::test]
    async fn serves() {
        let origins = vec!["example.org.".to_string()];
        let mut h = hf("10.0.0.1 a.example.org\n");
        h.origins = origins.clone();
        let hosts = Hosts {
            next: None,
            hf: Arc::new(h),
            origins: Arc::new(origins),
            fall: Arc::new(Fall::default()),
            fallthrough_unsupported: false,
            ttl: 3600,
        };
        let (rc, w) = serve(&hosts, &query("a.example.org.", RecordType::A, "10.0.0.9:1")).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        assert_eq!(
            w.msg().unwrap().answers[0].to_string(),
            "a.example.org. 3600 IN A 10.0.0.1"
        );
        // known name, other type: empty NOERROR
        let (_, w) = serve(&hosts, &query("a.example.org.", RecordType::MX, "10.0.0.9:1")).await;
        assert!(w.msg().unwrap().answers.is_empty());
        // unknown name without fallthrough: SERVFAIL from the server
        let (rc, _) = serve(&hosts, &query("b.example.org.", RecordType::A, "10.0.0.9:1")).await;
        assert_eq!(rc.unwrap(), ResponseCode::ServFail);
        let (_, w) = serve(&hosts, &query("1.0.0.10.in-addr.arpa.", RecordType::PTR, "10.0.0.9:1")).await;
        assert_eq!(
            w.msg().unwrap().answers[0].to_string(),
            "1.0.0.10.in-addr.arpa. 3600 IN PTR a.example.org."
        );
    }
}
