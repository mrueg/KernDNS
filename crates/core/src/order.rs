//! Plugin execution order.
//!
//! As in CoreDNS, the order in which plugins run is fixed by this list and
//! not by the order of directives in the Corefile. The list is CoreDNS
//! v1.15.0's `plugin.cfg`; a directive that isn't listed here is rejected as
//! unknown even if a plugin with that name is registered. A Go bridge built
//! with out-of-tree plugins adds their directives at the place its own
//! `dnsserver.Directives` puts them ([`add_directives`]), as CoreDNS's
//! `plugin.cfg` would for such a build.

use std::sync::RwLock;

pub const DIRECTIVES: &[&str] = &[
    "root",
    "metadata",
    "geoip",
    "cancel",
    "proxyproto",
    "quic",
    "grpc_server",
    "https",
    "https3",
    "timeouts",
    "multisocket",
    "reload",
    "nsid",
    "bufsize",
    "bind",
    "debug",
    "trace",
    "ready",
    "health",
    "pprof",
    "shed",
    "prometheus",
    "errors",
    "log",
    "dnstap",
    "local",
    "dns64",
    "siit",
    "any",
    "chaos",
    "loadbalance",
    "tsig",
    "rewrite",
    "autopath",
    "acl",
    "cache",
    "header",
    "dnssec",
    "tls",
    "minimal",
    "template",
    "transfer",
    "dynupdate",
    "hosts",
    "route53",
    "azure",
    "clouddns",
    "k8s_external",
    "kubernetes",
    "file",
    "auto",
    "secondary",
    "etcd",
    "loop",
    "forward",
    "grpc",
    "erratic",
    "whoami",
    "on",
    "sign",
    "view",
    "nomad",
];

/// The order with directives added by [`add_directives`]; empty if none were.
static EXTENDED: RwLock<Vec<&'static str>> = RwLock::new(Vec::new());

/// All directives in execution order.
pub fn directives() -> Vec<&'static str> {
    let ext = EXTENDED.read().unwrap();
    if ext.is_empty() {
        DIRECTIVES.to_vec()
    } else {
        ext.clone()
    }
}

/// Position of `name` in the execution order, if it is a known directive.
pub fn position(name: &str) -> Option<usize> {
    let ext = EXTENDED.read().unwrap();
    if ext.is_empty() {
        DIRECTIVES.iter().position(|d| *d == name)
    } else {
        ext.iter().position(|d| *d == name)
    }
}

/// Merge another directive order (a Go bridge's `dnsserver.Directives`)
/// into this one: each directive not known yet goes right after the one
/// before it in `order`, or first if it is first there.
pub fn add_directives(order: &[String]) {
    let mut ext = EXTENDED.write().unwrap();
    if ext.is_empty() {
        *ext = DIRECTIVES.to_vec();
    }
    merge(&mut ext, order);
}

fn merge(ext: &mut Vec<&'static str>, order: &[String]) {
    let mut after: Option<usize> = None;
    for name in order {
        let at = match ext.iter().position(|d| d == name) {
            Some(i) => i,
            None => {
                let i = after.map_or(0, |a| a + 1);
                ext.insert(i, Box::leak(name.clone().into_boxed_str()));
                i
            }
        };
        after = Some(at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_directives_keep_the_bridge_order() {
        let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // like a test that prepends its plugins, and one added in the middle
        let mut bridge = names(&["unready1", "unready2"]);
        bridge.extend(names(DIRECTIVES));
        let at = bridge.iter().position(|d| d == "whoami").unwrap();
        bridge.insert(at + 1, "extra".into());
        let mut d = DIRECTIVES.to_vec();
        merge(&mut d, &bridge);
        assert_eq!(&d[..3], &["unready1", "unready2", "root"]);
        let pos = |n: &str| d.iter().position(|x| *x == n).unwrap();
        assert_eq!(pos("extra"), pos("whoami") + 1);
        assert_eq!(d.len(), DIRECTIVES.len() + 3);
        // merging again changes nothing
        let before = d.clone();
        merge(&mut d, &bridge);
        assert_eq!(d, before);
    }
}
