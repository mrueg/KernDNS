//! `autopath`: server-side search path completion. Port of
//! `plugin/autopath`.
//!
//! ```text
//! autopath [ZONE...] RESOLV-CONF
//! ```
//!
//! RESOLV-CONF is a `resolv.conf`-like file whose `search` (or `domain`)
//! line gives the search path, or `@PLUGIN` to ask that plugin of the same
//! server block for a search path on every query. Plugins that can answer
//! implement [`AutoPather`] and register with [`AutoPathers`] during their
//! setup (`kubernetes` and `erratic` do).
//!
//! When the query name is in the first element of the search path, the
//! query is retried with each element in turn until one is not NXDOMAIN.
//! That answer gets a CNAME from the original name in front of it.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use kerndns_core::plugin::BlockHandlers;
use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::proto::rr::rdata::CNAME;
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record};
use kerndns_core::zones::{self, is_subdomain};
use kerndns_core::{
    BlockConfig, CaptureWriter, Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Request,
    ResponseWriter, SetupError, async_trait, client_write, next_or_failure,
};

use crate::pluginmetrics as pm;

const NAME: &str = "autopath";

/// A plugin that gives `autopath` a search path per query (CoreDNS's
/// `AutoPather` interface).
pub trait AutoPather: Send + Sync {
    /// The search path for this request, ending with the empty string
    /// (the sentinel for the name as asked). Empty means no autopathing.
    fn auto_path(&self, req: &Request) -> Vec<String>;
}

/// The plugins of a server block that implement [`AutoPather`], by
/// directive name. They register during setup; `autopath` looks its
/// `@PLUGIN` up when the server starts, like CoreDNS does with
/// `dnsserver.GetConfig(c).Handler(name)`.
#[derive(Clone, Default)]
pub struct AutoPathers(Arc<RwLock<HashMap<&'static str, Arc<dyn AutoPather>>>>);

impl AutoPathers {
    /// The registry of this block (created on first use).
    pub fn of(cfg: &mut BlockConfig) -> AutoPathers {
        if cfg.extensions.get::<AutoPathers>().is_none() {
            cfg.extensions.insert(AutoPathers::default());
        }
        cfg.extensions.get::<AutoPathers>().cloned().expect("inserted above")
    }

    pub fn register(&self, name: &'static str, p: Arc<dyn AutoPather>) {
        self.0.write().unwrap().insert(name, p);
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn AutoPather>> {
        self.0.read().unwrap().get(name).cloned()
    }
}

/// The `search` list of a `resolv.conf` file, like miekg/dns's
/// `ClientConfigFromReader`: the last `search` or `domain` line wins.
/// Elements are lowercased and fully qualified (`plugin.Zones.Normalize`).
pub fn resolv_conf_search(text: &str) -> Vec<String> {
    let mut search: Vec<String> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.first() {
            Some(&"domain") => search = f.get(1).map(|d| vec![d.to_string()]).unwrap_or_default(),
            Some(&"search") => search = f[1..].iter().map(|s| s.to_string()).collect(),
            _ => {}
        }
    }
    search.iter().map(|s| normalize(s)).collect()
}

/// `plugin.Name.Normalize`: lowercase and fully qualified.
fn normalize(s: &str) -> String {
    let mut s = s.to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// The handler.
pub struct AutoPath {
    next: Next,
    pub zones: Vec<String>,
    /// From the resolv.conf file; always ends with "" so the name as asked
    /// is tried too.
    pub search: Vec<String>,
    /// The `@PLUGIN` search path; takes precedence over `search`.
    search_func: Arc<OnceLock<Arc<dyn AutoPather>>>,
}

/// `firstInSearchPath`: `name` is the first search path element or below it.
fn first_in_search_path(name: &str, search: &[String]) -> bool {
    let first = search[0].to_ascii_lowercase();
    name == first || is_subdomain(&first, name)
}

/// `dnsutil.TrimZone`: `q` without the labels of `z` (and the dot before
/// them). `None` if that would leave nothing.
fn trim_zone(q: &Name, z: &str) -> Option<String> {
    let zl = Name::from_ascii(z).map(|n| n.num_labels()).ok()?;
    let ql = q.num_labels();
    if zl >= ql {
        return None;
    }
    let base = Name::from_labels(q.iter().take(usize::from(ql - zl))).ok()?;
    let mut s = base.to_ascii();
    if s.ends_with('.') {
        s.pop();
    }
    Some(s)
}

/// `cnamer`: put a CNAME from `original` to the owner of the first answer
/// with another name in front of the answers, and set the question name
/// back to `original`.
fn cnamer(m: &mut Message, original: &Name) {
    let orig = original.to_ascii().to_ascii_lowercase();
    if let Some(a) = m
        .answers
        .iter()
        .find(|a| a.name.to_ascii().to_ascii_lowercase() != orig)
    {
        let mut cname = Record::from_rdata(original.clone(), a.ttl, RData::CNAME(CNAME(a.name.clone())));
        cname.dns_class = DNSClass::IN;
        m.answers.insert(0, cname);
    }
    if let Some(q) = m.queries.first_mut() {
        q.set_name(original.clone());
    }
}

impl AutoPath {
    pub fn new(zones: Vec<String>, search: Vec<String>) -> Self {
        AutoPath {
            next: None,
            zones,
            search,
            search_func: Arc::default(),
        }
    }
}

#[async_trait]
impl Handler for AutoPath {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let name = req.name();
        if !self.zones.iter().any(|z| is_subdomain(z, &name)) {
            return next_or_failure(NAME, &self.next, ctx, w, req).await;
        }
        // the plugin's search path takes precedence over the configured one
        let from_func;
        let search: &[String] = match self.search_func.get() {
            Some(f) => {
                from_func = f.auto_path(req);
                &from_func
            }
            None => &self.search,
        };
        if search.is_empty() || !first_in_search_path(&name, search) {
            return next_or_failure(NAME, &self.next, ctx, w, req).await;
        }

        let orig_qname = req.qname().clone();
        // the base name, i.e. what the client asked before adding the
        // first search path element
        let Some(base) = trim_zone(&orig_qname, &search[0]) else {
            return Err(PluginError::servfail(
                NAME,
                format!(
                    "trimzone: overshot qname: {}for zone {}",
                    orig_qname.to_ascii(),
                    search[0]
                ),
            ));
        };

        let mut first: Option<(ResponseCode, Option<Message>)> = None;
        let mut ar = req.clone();
        // Walk the search path until an answer is not NXDOMAIN. If they all
        // are, return the first answer as is; the client then walks the
        // search path itself.
        for s in search {
            let Ok(qname) = Name::from_ascii(format!("{base}.{s}")) else {
                continue;
            };
            ar.msg.queries[0].set_name(qname);
            let mut nw = CaptureWriter::new();
            let rcode = next_or_failure(NAME, &self.next, ctx, &mut nw, &ar).await?;
            let msg = nw.msgs.pop();
            if first.is_none() {
                first = Some((rcode, msg.clone()));
            }
            if !client_write(rcode) {
                continue;
            }
            let Some(mut msg) = msg else { continue };
            if msg.metadata.response_code == ResponseCode::NXDomain {
                continue;
            }
            cnamer(&mut msg, &orig_qname);
            // write whatever non-NXDOMAIN answer we found
            let _ = w.write_msg(msg).await;
            pm::AUTOPATH_SUCCESS.with_label_values(&[&*ctx.server]).inc();
            return Ok(rcode);
        }
        let (rcode, msg) = first.unwrap_or((ResponseCode::NoError, None));
        if client_write(rcode)
            && let Some(m) = msg
        {
            let _ = w.write_msg(m).await;
        }
        Ok(rcode)
    }
}

/// `autoPathParse`: the handler and the `@PLUGIN` name (empty for a file).
fn parse(c: &mut Controller<'_>) -> Result<(AutoPath, String), SetupError> {
    let err = |m: String| SetupError::new(NAME, m);
    let mut ap = AutoPath::new(Vec::new(), Vec::new());
    let mut mw = String::new();
    let server_keys = c.server_block_keys();
    while c.next() {
        let args = c.remaining_args();
        let Some((resolv, zones)) = args.split_last() else {
            return Err(err("no resolv-conf specified".into()));
        };
        if let Some(p) = resolv.strip_prefix('@') {
            mw = p.to_string();
        } else {
            let text = std::fs::read_to_string(resolv)
                .map_err(|e| err(format!("failed to parse {resolv:?}: {}", open_error(resolv, &e))))?;
            ap.search = resolv_conf_search(&text);
            ap.search.push(String::new()); // the sentinel
        }
        ap.zones = zones::origins_from_args_or_server_block(zones, &server_keys);
    }
    Ok((ap, mw))
}

/// The error of Go's `os.Open`.
fn open_error(path: &str, e: &std::io::Error) -> String {
    let msg = match e.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        std::io::ErrorKind::IsADirectory => "is a directory".to_string(),
        _ => e.to_string(),
    };
    match e.kind() {
        // reading a directory fails on read, not open
        std::io::ErrorKind::IsADirectory => format!("read {path}: {msg}"),
        _ => format!("open {path}: {msg}"),
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let (ap, mw) = parse(c)?;
        let func = ap.search_func.clone();
        if !mw.is_empty() {
            // done at startup, when every plugin of the block is set up
            let pathers = AutoPathers::of(c.config);
            let handlers = BlockHandlers::of(c.config);
            c.on_startup(move || {
                if let Some(p) = pathers.get(&mw) {
                    let _ = func.set(p);
                } else if handlers.contains(&mw) {
                    return Err(format!("{mw} does not implement the AutoPather interface"));
                }
                Ok(())
            });
        }
        let ap = Arc::new(ap);
        c.add_plugin(move |next| {
            Arc::new(AutoPath {
                next,
                zones: ap.zones.clone(),
                search: ap.search.clone(),
                search_func: ap.search_func.clone(),
            })
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::zonefile::new_rr;
    use crate::testutil::*;
    use kerndns_core::corefile::{Dispenser, parse as parse_corefile};
    use kerndns_core::proto::rr::RecordType;
    use kerndns_core::{Hooks, ZoneAddr};

    const DEFAULT_A: &str = " 3600 IN A 127.0.0.53";

    /// `nextHandler`: NXDOMAIN or an A record per name, SERVFAIL (not
    /// written) for other names.
    struct NextHandler(HashMap<&'static str, ResponseCode>);

    #[async_trait]
    impl Handler for NextHandler {
        fn name(&self) -> &'static str {
            "next"
        }

        async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, r: &Request) -> HandlerResult {
            let qname = r.qname().to_ascii();
            let Some(&rcode) = self.0.get(qname.as_str()) else {
                return Ok(ResponseCode::ServFail);
            };
            let mut m = r.reply();
            m.metadata.response_code = rcode;
            match rcode {
                ResponseCode::NXDomain => m.authorities.push(
                    new_rr("example.org. 1800 IN SOA example.org. example.org. 1502165581 14400 3600 604800 14400")
                        .unwrap()
                        .unwrap(),
                ),
                ResponseCode::NoError => m.answers.push(new_rr(&format!("{qname}{DEFAULT_A}")).unwrap().unwrap()),
                _ => panic!("nextHandler: unhandled rcode"),
            }
            w.write_msg(m).await.unwrap();
            Ok(rcode)
        }
    }

    fn new_test_autopath() -> AutoPath {
        let mut ap = AutoPath::new(
            vec![".".into()],
            vec![
                "example.org.".into(),
                "example.com.".into(),
                "com.".into(),
                String::new(),
            ],
        );
        ap.next = Some(Arc::new(NextHandler(HashMap::from([
            ("b.example.org.", ResponseCode::NXDomain),
            ("b.com.", ResponseCode::NoError),
            ("a.example.com.", ResponseCode::NoError),
        ]))));
        ap
    }

    fn answers(m: &Message) -> Vec<String> {
        m.answers.iter().map(|r| r.to_string()).collect()
    }

    // autopath_test.go: TestAutoPath
    #[tokio::test]
    async fn autopath() {
        let ap = new_test_autopath();
        // search path expansion
        let (rc, w) = serve(&ap, &query("b.example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        let m = w.msg().unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert_eq!(m.queries[0].name().to_ascii(), "b.example.org.");
        // the CNAME sits before the rest of the answer
        assert_eq!(
            answers(m),
            ["b.example.org. 3600 IN CNAME b.com.", "b.com. 3600 IN A 127.0.0.53"]
        );
        assert!(m.authorities.is_empty() && m.additionals.is_empty());

        // no search path expansion
        let (rc, w) = serve(&ap, &query("a.example.com.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        assert_eq!(answers(w.msg().unwrap()), ["a.example.com. 3600 IN A 127.0.0.53"]);
    }

    // autopath_test.go: TestAutoPathNoAnswer
    #[tokio::test]
    async fn no_answer() {
        let ap = new_test_autopath();
        let (rc, _) = serve(&ap, &query("c.example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert!(!client_write(rc.unwrap()), "expected no client write");
    }

    // autopath_test.go: TestAutoPathNilMsgFromNext
    #[tokio::test]
    async fn nil_msg_from_next() {
        struct Silent;
        #[async_trait]
        impl Handler for Silent {
            fn name(&self) -> &'static str {
                "silent"
            }
            async fn serve_dns(&self, _: &mut Context, _: &mut dyn ResponseWriter, _: &Request) -> HandlerResult {
                // like acl's drop: success without a response
                Ok(ResponseCode::NoError)
            }
        }
        let mut ap = AutoPath::new(
            vec![".".into()],
            vec![
                "example.org.".into(),
                "example.com.".into(),
                "com.".into(),
                String::new(),
            ],
        );
        ap.next = Some(Arc::new(Silent));
        let (rc, w) = serve(&ap, &query("b.example.org.", RecordType::A, "10.0.0.1:53")).await;
        rc.unwrap();
        assert!(!w.written(), "expected no client write");
    }

    // autopath_test.go: TestInSearchPath
    #[test]
    fn in_search_path() {
        let search: Vec<String> = ["default.svc.cluster.local.", "svc.cluster.local.", "cluster.local."]
            .map(String::from)
            .to_vec();
        let tests = [
            ("google.com", false),
            ("default.svc.cluster.local.", true),
            ("a.default.svc.cluster.local.", true),
            ("a.b.svc.cluster.local.", false),
        ];
        for (i, (qname, want)) in tests.into_iter().enumerate() {
            assert_eq!(first_in_search_path(qname, &search), want, "test {i}");
        }
    }

    #[test]
    fn trim_zones() {
        let n = |s: &str| Name::from_ascii(s).unwrap();
        assert_eq!(
            trim_zone(&n("a.B.example.org."), "example.org.").as_deref(),
            Some("a.B")
        );
        assert_eq!(trim_zone(&n("a.example.org."), ".").as_deref(), Some("a.example.org"));
        assert_eq!(trim_zone(&n("example.org."), "example.org."), None);
    }

    #[tokio::test]
    async fn qname_is_first_element() {
        // CoreDNS's TrimZone overshoots: SERVFAIL
        let ap = new_test_autopath();
        let (rc, _) = serve(&ap, &query("example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(rc.unwrap_err().rcode, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn success_metric() {
        let ap = new_test_autopath();
        let server = "dns://:5353";
        let get = || pm::AUTOPATH_SUCCESS.with_label_values(&[server]).get();
        let before = get();
        let mut ctx = Context::new(".", server);
        let mut w = CaptureWriter::new();
        let req = query("b.example.org.", RecordType::A, "10.0.0.1:53");
        ap.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
        assert_eq!(get(), before + 1.0);
        // all NXDOMAIN: no success
        let req = query("c.example.org.", RecordType::A, "10.0.0.1:53");
        let _ = ap.serve_dns(&mut ctx, &mut w, &req).await;
        // not in the search path: no success
        let req = query("a.example.com.", RecordType::A, "10.0.0.1:53");
        ap.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
        assert_eq!(get(), before + 1.0);
    }

    struct Fixed(Vec<String>);

    impl AutoPather for Fixed {
        fn auto_path(&self, _: &Request) -> Vec<String> {
            self.0.clone()
        }
    }

    #[tokio::test]
    async fn search_func_takes_precedence() {
        let ap = new_test_autopath();
        ap.search_func
            .set(Arc::new(Fixed(vec!["foo.org.".into(), "com.".into(), String::new()])))
            .ok()
            .unwrap();
        let (_, w) = serve(&ap, &query("b.foo.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(
            answers(w.msg().unwrap()),
            ["b.foo.org. 3600 IN CNAME b.com.", "b.com. 3600 IN A 127.0.0.53"]
        );
        // an empty search path: no autopath
        let ap = new_test_autopath();
        let _ = ap.search_func.set(Arc::new(Fixed(Vec::new())));
        let (rc, _) = serve(&ap, &query("b.example.org.", RecordType::A, "10.0.0.1:53")).await;
        assert_eq!(rc.unwrap(), ResponseCode::NXDomain);
    }

    fn parse_autopath(input: &str) -> Result<(AutoPath, String), String> {
        let blocks = parse_corefile(&format!(".:53 {{\n{input}\n}}"), "Corefile").expect("parses");
        let mut cfg = BlockConfig::new(ZoneAddr::parse(".:53", "53").unwrap());
        let mut hooks = Hooks::default();
        let mut c = Controller::new(
            NAME,
            Dispenser::new(blocks[0].tokens_for(NAME)),
            &mut cfg,
            &mut hooks,
            ".".into(),
        );
        parse(&mut c).map_err(|e| e.to_string())
    }

    // setup_test.go: TestSetupAutoPath
    #[test]
    fn setup_autopath() {
        let dir = std::env::temp_dir().join(format!("kerndns-autopath-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let resolv = dir.join("resolv.conf");
        std::fs::write(
            &resolv,
            "nameserver 1.2.3.4\ndomain foo.com\nsearch bar.com baz.com\noptions ndots:5\n",
        )
        .unwrap();
        let resolv = resolv.display().to_string();

        // (input, zone, plugin, search)
        let oks: [(String, &str, &str, Option<Vec<&str>>); 4] = [
            ("autopath @kubernetes".into(), "", "kubernetes", None),
            (
                "autopath example.org @kubernetes".into(),
                "example.org.",
                "kubernetes",
                None,
            ),
            (
                "autopath 10.0.0.0/8 @kubernetes".into(),
                "10.in-addr.arpa.",
                "kubernetes",
                None,
            ),
            (
                format!("autopath {resolv}"),
                "",
                "",
                Some(vec!["bar.com.", "baz.com.", ""]),
            ),
        ];
        for (input, zone, mw, search) in oks {
            let (ap, got_mw) = parse_autopath(&input).unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(got_mw, mw, "{input}");
            if let Some(s) = search {
                assert_eq!(ap.search, s, "{input}");
            }
            if !zone.is_empty() {
                assert_eq!(ap.zones[0], zone, "{input}");
            }
        }

        let fails = [
            (
                "autopath kubernetes",
                "plugin/autopath: failed to parse \"kubernetes\": open kubernetes: no such file or directory",
            ),
            ("autopath", "plugin/autopath: no resolv-conf specified"),
            (
                "autopath \"\"",
                "plugin/autopath: failed to parse \"\": open : no such file or directory",
            ),
        ];
        for (input, want) in fails {
            assert_eq!(parse_autopath(input).err().as_deref(), Some(want), "{input}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolv_conf() {
        assert_eq!(
            resolv_conf_search("search A.com b.com\nnameserver 1.1.1.1\n"),
            ["a.com.", "b.com."]
        );
        assert_eq!(resolv_conf_search("search a.com\ndomain x.org\n"), ["x.org."]);
        assert!(resolv_conf_search("nameserver 1.1.1.1\n").is_empty());
    }

    /// Set up `input` in a block that also has `loaded` handlers (each
    /// answering like [`NextHandler`]), optionally with an AutoPather
    /// registered as `erratic`, then run the startup hooks.
    fn startup(input: &str, loaded: &[&'static str], pather: bool) -> Result<Next, String> {
        let blocks = parse_corefile(&format!(".:53 {{\n{input}\n}}"), "Corefile").unwrap();
        let mut cfg = BlockConfig::new(ZoneAddr::parse(".:53", "53").unwrap());
        let mut hooks = Hooks::default();
        {
            let mut c = Controller::new(
                NAME,
                Dispenser::new(blocks[0].tokens_for(NAME)),
                &mut cfg,
                &mut hooks,
                ".".into(),
            );
            Setup.setup(&mut c).map_err(|e| e.to_string())?;
        }
        for name in loaded {
            cfg.plugins.push((
                name,
                Arc::new(|_| {
                    Arc::new(NextHandler(HashMap::from([
                        ("b.example.org.", ResponseCode::NXDomain),
                        ("b.com.", ResponseCode::NoError),
                    ]))) as Arc<dyn Handler>
                }),
            ));
        }
        if pather {
            AutoPathers::of(&mut cfg).register(
                "erratic",
                Arc::new(Fixed(vec!["example.org.".into(), "com.".into(), String::new()])),
            );
        }
        BlockHandlers::fill(&mut cfg);
        for (_, hook) in hooks.startup {
            hook()?;
        }
        Ok(cfg.chain())
    }

    #[tokio::test]
    async fn startup_lookup() {
        let q = query("b.example.org.", RecordType::A, "10.0.0.1:53");
        // the named plugin implements AutoPather: its search path is used
        let chain = startup("autopath @erratic", &["erratic"], true).unwrap().unwrap();
        let (_, w) = serve(&*chain, &q).await;
        assert_eq!(
            answers(w.msg().unwrap()),
            ["b.example.org. 3600 IN CNAME b.com.", "b.com. 3600 IN A 127.0.0.53"]
        );

        // loaded, but not an AutoPather
        assert_eq!(
            startup("autopath @whoami", &["whoami"], false).err().as_deref(),
            Some("whoami does not implement the AutoPather interface")
        );

        // not loaded at all: no autopath, no error
        let chain = startup("autopath @kubernetes", &["erratic"], true).unwrap().unwrap();
        let (rc, _) = serve(&*chain, &q).await;
        assert_eq!(rc.unwrap(), ResponseCode::NXDomain);
    }
}
