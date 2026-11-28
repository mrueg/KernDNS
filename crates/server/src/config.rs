//! Corefile → plugin chains → listeners, like CoreDNS's
//! `dnsserver/register.go` (InspectServerBlocks, MakeServers).

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use kerndns_core::corefile::{Dispenser, ParseError, parse};
use kerndns_core::{BlockConfig, Controller, Hooks, Next, Registry, SetupError, Transport, ZoneAddr, order};

/// Plugins whose presence unblocks CH-class queries (`dnsserver.EnableChaos`).
pub const ENABLE_CHAOS: &[&str] = &["chaos", "forward", "proxy"];

/// Errors while loading a Corefile.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    Setup(#[from] SetupError),
    #[error("{0}")]
    Other(String),
}

/// Settings that come from the command line rather than the Corefile.
#[derive(Debug, Clone)]
pub struct Options {
    /// Port for keys without one (`-dns.port`).
    pub dns_port: String,
}

impl Default for Options {
    fn default() -> Self {
        Self { dns_port: "53".into() }
    }
}

/// The plugin chain serving one zone.
pub struct ZoneHandler {
    pub zone: Arc<str>,
    /// `None` if the block has no plugins that handle queries; the server
    /// answers REFUSED for such zones, like CoreDNS.
    pub chain: Next,
    pub debug: bool,
    pub allow_update: bool,
    /// `FilterFuncs` of the block (`view`).
    pub filters: Vec<Arc<dyn kerndns_core::plugin::RequestFilter>>,
    pub view_name: Option<String>,
    /// Set when the block runs the `metadata` plugin.
    pub metadata: Option<kerndns_core::plugin::Metadata>,
}

/// One listen address with the zones it serves.
pub struct ListenerPlan {
    pub transport: Transport,
    /// Host to bind, "" for all interfaces.
    pub host: String,
    pub port: String,
    /// Zone handlers in Corefile order.
    pub zones: Vec<(String, Arc<ZoneHandler>)>,
    pub class_chaos: bool,
    /// Server TLS for `tls://` and `https://` (from the `tls` plugin).
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// TCP/DoT timeouts merged from the listener's blocks (`timeouts`).
    pub conn: kerndns_core::plugin::ConnLimits,
    /// `multisocket` of the first block on this address: that many UDP
    /// sockets and TCP listeners, each a server of its own. 0 if not set.
    pub num_sockets: usize,
    /// DoH/DoH3/gRPC/DoQ limits: those of the listener's first zone, like
    /// CoreDNS's `group[0]` (DoH's `max_streams` from any zone).
    pub limits: kerndns_core::plugin::ListenerLimits,
    /// Decorates the UDP sockets' writes (`shed`); the last block on the
    /// listener that sets one wins, like CoreDNS.
    pub udp_decorator: Option<Arc<dyn kerndns_core::udpwrite::UdpDecorator>>,
    /// PROXY protocol settings merged from the listener's blocks.
    pub proxy_proto: Option<Arc<kerndns_core::proxyproto::ProxyProtoConfig>>,
}

impl ListenerPlan {
    /// e.g. `dns://:53` or `dns://127.0.0.1:1053`.
    pub fn label(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{}://{}:{}", self.transport, host, self.port)
    }
}

/// Everything needed to start serving.
pub struct Plan {
    pub listeners: Vec<ListenerPlan>,
    pub hooks: Hooks,
    /// What setup replaced of the running configuration's global state,
    /// put back if this plan fails to start on reload.
    pub(crate) previous: Option<Previous>,
}

/// The readiness checks and `reload` interval of the configuration that
/// was running while a plan was loaded.
pub(crate) struct Previous {
    readiness: kerndns_core::readiness::Saved,
    reload: Option<std::time::Duration>,
}

impl Previous {
    fn save() -> Self {
        Self {
            readiness: kerndns_core::readiness::save(),
            reload: kerndns_core::reload::interval(),
        }
    }

    pub(crate) fn restore(self) {
        kerndns_core::readiness::restore(self.readiness);
        kerndns_core::reload::restore(self.reload);
    }
}

/// The Corefile used when there is none, or it has no server blocks, like
/// CoreDNS's `DefaultInput`.
pub fn default_corefile(port: &str) -> String {
    format!(".:{port} {{\n    whoami\n    log\n}}\n")
}

/// Parse a Corefile and run every plugin's setup.
///
/// Setup registers readiness checks and the `reload` interval globally; if
/// it fails (or the plan fails to start on reload), those of the running
/// configuration are put back, so a failed reload leaves `ready` and
/// `reload` as they were.
pub fn load(corefile: &str, path: &str, registry: &Registry, opts: &Options) -> Result<Plan, LoadError> {
    let mut blocks = parse(corefile, path)?;
    if blocks.is_empty() {
        // caddy loads the server type's DefaultInput then
        blocks = parse(&default_corefile(&opts.dns_port), "Corefile")?;
    }
    let saved = Previous::save();
    kerndns_core::readiness::reset();
    kerndns_core::reload::reset();
    match setup(&blocks, path, registry, opts) {
        Ok(mut plan) => {
            plan.previous = Some(saved);
            Ok(plan)
        }
        Err(e) => {
            saved.restore();
            Err(e)
        }
    }
}

fn setup(
    blocks: &[kerndns_core::corefile::ServerBlock],
    path: &str,
    registry: &Registry,
    opts: &Options,
) -> Result<Plan, LoadError> {
    let corefile_dir = Path::new(path).parent().map(Path::to_path_buf).unwrap_or_default();
    let mut hooks = Hooks::default();
    let mut seen: HashSet<ZoneAddr> = HashSet::new();
    let mut configs: Vec<BlockConfig> = Vec::new();

    for block in blocks {
        let mut keys = Vec::new();
        for key in &block.keys {
            let addrs = ZoneAddr::parse(key, &opts.dns_port)
                .map_err(|e| LoadError::Parse(ParseError::at(&block.key_token, e)))?;
            keys.extend(addrs);
        }
        for d in &block.directives {
            if order::position(&d.name).is_none() {
                return Err(ParseError::at(&d.tokens[0], format!("Unknown directive '{}'", d.name)).into());
            }
            if registry.get(&d.name).is_none() {
                return Err(ParseError::at(
                    &d.tokens[0],
                    format!(
                        "Directive '{}' is not available in KernDNS yet (no Rust port of this plugin)",
                        d.name
                    ),
                )
                .into());
            }
        }

        check_affinity(
            &block.directives.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            registry,
        )?;
        let mut cfg = BlockConfig::new(keys);
        for name in order::directives() {
            let tokens = block.tokens_for(name);
            if tokens.is_empty() {
                continue;
            }
            let factory = registry.get(name).expect("checked above").clone();
            let mut c = Controller::new(name, Dispenser::new(tokens), &mut cfg, &mut hooks, corefile_dir.clone());
            factory.setup(&mut c)?;
        }
        // like validateZonesAndListeningAddresses: a block with filters
        // (`view`) may share its zone with others
        if cfg.filters.is_empty() {
            for za in &cfg.keys {
                if !seen.insert(za.clone()) {
                    return Err(LoadError::Other(format!("cannot serve {za} - it is already defined")));
                }
            }
        }
        configs.push(cfg);
    }

    for cfg in &mut configs {
        add_to_all_blocks(cfg, &hooks.all_blocks);
        kerndns_core::plugin::BlockHandlers::fill(cfg);
        if cfg.plugins.iter().any(|(n, _)| *n == "prometheus") {
            // coredns_plugin_enabled for every handler in the block
            let hosts = if cfg.listen_hosts.is_empty() {
                vec![String::new()]
            } else {
                cfg.listen_hosts.clone()
            };
            for key in &cfg.keys {
                for h in &hosts {
                    let host = if h.contains(':') { format!("[{h}]") } else { h.clone() };
                    let server = format!("{}://{}:{}", key.transport, host, key.port);
                    for (name, _) in &cfg.plugins {
                        kerndns_core::metrics::PLUGIN_ENABLED
                            .with_label_values(&[&server, &key.zone, "", name])
                            .set(1.0);
                    }
                }
            }
        }
    }

    Ok(Plan {
        listeners: group_by_listener(&configs)?,
        hooks,
        previous: None,
    })
}

/// Insert the handlers that setup added to every block
/// (`AddPluginToAllServerBlocks`). CoreDNS runs each directive across all
/// blocks before the next, so such a handler ends up after the block's
/// handlers from earlier directives and before those from later ones.
fn add_to_all_blocks(cfg: &mut BlockConfig, all: &[(&'static str, kerndns_core::PluginFn)]) {
    for (name, f) in all {
        let pos = order::position(name).unwrap_or(usize::MAX);
        let at = cfg
            .plugins
            .iter()
            .position(|(n, _)| order::position(n).unwrap_or(usize::MAX) > pos)
            .unwrap_or(cfg.plugins.len());
        cfg.plugins.insert(at, (name, f.clone()));
    }
}

/// Plugins that work together through Go types (CoreDNS looks them up with
/// `Config.Handler`), so in one server block they must all run on the same
/// side of the Go bridge. A group only applies if its first plugin is there.
const AFFINITY: &[&[&str]] = &[
    &["k8s_external", "kubernetes"],
    &["transfer", "file", "secondary", "auto", "kubernetes", "dynupdate"],
    &["alternate", "forward"],
    &["autopath", "kubernetes", "erratic"],
];

fn check_affinity(directives: &[&str], registry: &Registry) -> Result<(), LoadError> {
    for group in AFFINITY {
        if !directives.contains(&group[0]) {
            continue;
        }
        let present: Vec<(&str, bool)> = group
            .iter()
            .filter(|n| directives.contains(n))
            .filter_map(|n| registry.get(n).map(|f| (*n, f.bridged())))
            .collect();
        let go: Vec<&str> = present.iter().filter(|(_, b)| *b).map(|(n, _)| *n).collect();
        let rust: Vec<&str> = present.iter().filter(|(_, b)| !*b).map(|(n, _)| *n).collect();
        if !go.is_empty() && !rust.is_empty() {
            return Err(LoadError::Other(format!(
                "plugins {} (Go bridge) and {} (Rust) work together and must run on the same side; \
                 use -bridge.prefer to run them all in Go",
                go.join(", "),
                rust.join(", ")
            )));
        }
    }
    Ok(())
}

/// One listener per (transport, host, port), like `groupConfigsByListenAddr`.
fn group_by_listener(configs: &[BlockConfig]) -> Result<Vec<ListenerPlan>, LoadError> {
    let mut listeners: Vec<ListenerPlan> = Vec::new();
    // DoH max_streams per listener, resolved across all its zones
    let mut https_streams: Vec<Option<u64>> = Vec::new();
    for cfg in configs {
        let hosts = if cfg.listen_hosts.is_empty() {
            vec![String::new()]
        } else {
            cfg.listen_hosts.clone()
        };
        for (i, key) in cfg.keys.iter().enumerate() {
            // setup ran for the block's first key only
            let limits = if i == 0 { cfg.limits } else { cfg.limits.propagated() };
            let handler = Arc::new(ZoneHandler {
                zone: Arc::from(key.zone.as_str()),
                chain: cfg.chain(),
                debug: cfg.debug,
                allow_update: cfg.allow_update,
                filters: cfg.filters.clone(),
                view_name: cfg.view_name.clone(),
                metadata: kerndns_core::plugin::Metadata::enabled_in(cfg),
            });
            for host in &hosts {
                let pos = listeners
                    .iter()
                    .position(|l| l.transport == key.transport && &l.host == host && l.port == key.port);
                let idx = match pos {
                    Some(i) => i,
                    None => {
                        listeners.push(ListenerPlan {
                            transport: key.transport,
                            host: host.clone(),
                            port: key.port.clone(),
                            zones: Vec::new(),
                            class_chaos: false,
                            tls: None,
                            conn: Default::default(),
                            num_sockets: cfg.num_sockets,
                            limits,
                            udp_decorator: None,
                            proxy_proto: None,
                        });
                        https_streams.push(None);
                        listeners.len() - 1
                    }
                };
                if let Some(n) = limits.https_max_streams {
                    match https_streams[idx] {
                        Some(prev) if prev != n => {
                            return Err(LoadError::Other(format!(
                                "conflicting max_streams values for shared HTTPS listener {}: {prev} and {n}",
                                listeners[idx].label()
                            )));
                        }
                        _ => https_streams[idx] = Some(n),
                    }
                }
                let l = &mut listeners[idx];
                l.class_chaos |= cfg.class_chaos || cfg.plugins.iter().any(|(n, _)| ENABLE_CHAOS.contains(n));
                if l.tls.is_none() {
                    l.tls = cfg.tls.clone();
                }
                l.conn.merge(&cfg.conn);
                if let Some(pp) = &cfg.proxy_proto {
                    let mut merged = l.proxy_proto.as_deref().cloned().unwrap_or_default();
                    merged.merge(pp);
                    l.proxy_proto = Some(Arc::new(merged));
                }
                if cfg.udp_decorator.is_some() {
                    l.udp_decorator = cfg.udp_decorator.clone();
                }
                l.zones.push((key.zone.clone(), handler.clone()));
            }
        }
    }
    for (l, streams) in listeners.iter_mut().zip(https_streams) {
        l.limits.https_max_streams = streams;
    }
    Ok(listeners)
}

#[cfg(test)]
mod tests {
    /// A stand-in for a plugin served by the Go bridge.
    struct FakeGo(&'static str);

    impl kerndns_core::PluginFactory for FakeGo {
        fn name(&self) -> &'static str {
            self.0
        }
        fn setup(&self, c: &mut kerndns_core::Controller<'_>) -> Result<(), SetupError> {
            while c.next() {}
            Ok(())
        }
        fn bridged(&self) -> bool {
            true
        }
    }

    /// CoreDNS's import README example is a Corefile with only a snippet;
    /// caddy serves its default Corefile then instead of failing.
    #[test]
    fn no_server_blocks_loads_the_default() {
        let reg = kerndns_plugins::registry();
        let opts = Options {
            dns_port: "1053".into(),
        };
        for corefile in ["", "# nothing\n", "(mysnippet) {\n\t...\n}\n"] {
            let plan = load(corefile, "Corefile", &reg, &opts).unwrap_or_else(|e| panic!("{corefile:?}: {e}"));
            let labels: Vec<String> = plan.listeners.iter().map(|l| l.label()).collect();
            assert_eq!(labels, ["dns://:1053"], "{corefile:?}");
            assert_eq!(plan.listeners[0].zones[0].0, ".", "{corefile:?}");
        }
    }

    #[test]
    fn affinity_groups() {
        let mut reg = kerndns_plugins::registry();
        reg.register(FakeGo("kubernetes"));
        // transfer (Rust) + kubernetes (Go) in one block: refused
        let e = load(
            ".:53 {\n transfer {\n to *\n }\n kubernetes\n}",
            "Corefile",
            &reg,
            &Options::default(),
        )
        .err()
        .expect("split group")
        .to_string();
        assert!(e.contains("kubernetes (Go bridge) and transfer (Rust)"), "{e}");
        // the same plugins in different blocks are fine
        assert!(
            load(
                ".:53 {\n kubernetes\n}\nexample.org:53 {\n transfer {\n to *\n }\n}",
                "Corefile",
                &reg,
                &Options::default()
            )
            .is_ok()
        );
    }

    use super::*;

    fn load_str(s: &str) -> Result<Plan, LoadError> {
        load(s, "Corefile", &kerndns_plugins::registry(), &Options::default())
    }

    #[test]
    fn groups_zones_by_port() {
        let p =
            load_str("example.org:1053 {\n whoami\n}\nexample.net:1053 {\n whoami\n}\n.:1054 {\n whoami\n}").unwrap();
        assert_eq!(p.listeners.len(), 2);
        assert_eq!(p.listeners[0].label(), "dns://:1053");
        assert_eq!(p.listeners[0].zones.len(), 2);
        assert_eq!(p.listeners[1].label(), "dns://:1054");
    }

    #[test]
    fn bind_splits_listeners() {
        let p = load_str(".:1053 {\n bind 127.0.0.1 ::1\n whoami\n}").unwrap();
        let labels: Vec<_> = p.listeners.iter().map(|l| l.label()).collect();
        assert_eq!(labels, vec!["dns://127.0.0.1:1053", "dns://[::1]:1053"]);
    }

    #[test]
    fn errors() {
        let e = load_str(".:53 {\n foo\n}").err().unwrap().to_string();
        assert_eq!(e, "Corefile:2 - Error during parsing: Unknown directive 'foo'");
        let e = load_str(".:53 {\n kubernetes\n}").err().unwrap().to_string();
        assert!(e.contains("not available in KernDNS yet"), "{e}");
        let e = load_str(".:53 {\n whoami\n}\n.:53 {\n whoami\n}")
            .err()
            .unwrap()
            .to_string();
        assert_eq!(e, "cannot serve dns://.:53 - it is already defined");
        let e = load_str(".:53 {\n whoami x\n}").err().unwrap().to_string();
        assert!(e.starts_with("plugin/whoami: Corefile:2"), "{e}");
    }

    #[test]
    fn listener_limits_follow_coredns() {
        let limits = |corefile: &str, scheme: &str| {
            let p = load_str(corefile).unwrap();
            p.listeners
                .iter()
                .find(|l| l.label().starts_with(scheme))
                .unwrap()
                .limits
        };
        // setup runs for the first key only, so the gRPC key sees the
        // limit only when it comes first...
        let first = limits("grpc://.:1053 .:1054 {\n grpc_server {\n  max_streams 2\n }\n}", "grpc");
        assert_eq!(first.grpc_max_streams, Some(2));
        let second = limits(".:1054 grpc://.:1053 {\n grpc_server {\n  max_streams 2\n }\n}", "grpc");
        assert_eq!(second.grpc_max_streams, None);
        // ...except DoH's max_streams and DoQ's max_connections, which are
        // copied to every key
        let doq = limits(
            ".:1054 quic://.:1053 {\n quic {\n  max_connections 3\n  max_streams 4\n }\n}",
            "quic",
        );
        assert_eq!((doq.quic_max_connections, doq.quic_max_streams), (Some(3), None));
        let doh = limits(".:1054 https://.:1053 {\n https {\n  max_streams 5\n }\n}", "https");
        assert_eq!(doh.https_max_streams, Some(5));
        // the listener's first zone decides
        let two = limits(
            "grpc://a.:1053 {\n whoami\n}\ngrpc://b.:1053 {\n grpc_server {\n  max_connections 1\n }\n}",
            "grpc",
        );
        assert_eq!(two.grpc_max_connections, None);
    }

    #[test]
    fn empty_block_has_no_chain() {
        let p = load_str("example.org:1053 {\n}").unwrap();
        assert!(p.listeners[0].zones[0].1.chain.is_none());
    }
}
