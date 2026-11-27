//! `autopath @kubernetes`: the search path of the pod that sent the query,
//! like `plugin/kubernetes/autopath.go`.

use std::sync::Arc;

use kerndns_core::Request;
use kerndns_core::zones;
use kerndns_plugins::autopath::{AutoPather, resolv_conf_search};

use crate::object::Pod;
use crate::{Kubernetes, PodMode};

/// `searchFromResolvConf`: the search path of `/etc/resolv.conf`, empty if
/// it can't be read.
pub(crate) fn search_from_resolv_conf() -> Vec<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|t| resolv_conf_search(&t))
        .unwrap_or_default()
}

impl Kubernetes {
    /// `podWithIP`: the pod with the client's address (`pods verified` only).
    pub(crate) fn pod_with_ip(&self, ip: &str) -> Option<Arc<Pod>> {
        if self.pod_mode != PodMode::Verified {
            return None;
        }
        self.api()?.pod_index(ip).into_iter().next()
    }
}

impl AutoPather for Kubernetes {
    /// `AutoPath`: `<namespace>.svc.<zone>`, `svc.<zone>`, `<zone>`, then
    /// the server's own search path, for a query from a known pod in one of
    /// the plugin's zones. Empty (no autopath) otherwise.
    fn auto_path(&self, req: &Request) -> Vec<String> {
        // only for queries in a zone we are authoritative for
        let Some(zone) = zones::matches(&self.zones, &req.name()) else {
            return Vec::new();
        };
        // without `pods verified` there is no pod cache
        let Some(pod) = self.pod_with_ip(&req.ip().to_string()) else {
            return Vec::new();
        };
        let mut search = Vec::with_capacity(4 + self.auto_path_search.len());
        if zone == "." {
            search.push(format!("{}.svc.", pod.namespace));
            search.push("svc.".to_string());
            search.push(".".to_string());
        } else {
            search.push(format!("{}.svc.{zone}", pod.namespace));
            search.push(format!("svc.{zone}"));
            search.push(zone.to_string());
        }
        search.extend(self.auto_path_search.iter().cloned());
        search.push(String::new()); // the sentinel
        search
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Setup;
    use crate::controller::DnsController;
    use crate::object::{Endpoints, Service};
    use kerndns_core::corefile::{Dispenser, parse};
    use kerndns_core::plugin::BlockHandlers;
    use kerndns_core::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use kerndns_core::proto::rr::{Name, RecordType};
    use kerndns_core::{BlockConfig, CaptureWriter, Context, Controller, Hooks, PluginFactory, Protocol, ZoneAddr};
    use kerndns_plugins::autopath::AutoPathers;

    /// A fake API with one pod and one service.
    struct Fake;

    impl DnsController for Fake {
        fn svc_index(&self, idx: &str) -> Vec<Arc<Service>> {
            if idx != "svc1.testns" {
                return Vec::new();
            }
            vec![Arc::new(Service {
                name: "svc1".into(),
                namespace: "testns".into(),
                index: "svc1.testns".into(),
                cluster_ips: vec!["10.0.0.1".into()],
                type_: "ClusterIP".into(),
                ports: vec![crate::object::ServicePort {
                    name: "http".into(),
                    protocol: "TCP".into(),
                    port: 80,
                }],
                ..Default::default()
            })]
        }
        fn svc_index_reverse(&self, _: &str) -> Vec<Arc<Service>> {
            Vec::new()
        }
        fn svc_ext_index_reverse(&self, _: &str) -> Vec<Arc<Service>> {
            Vec::new()
        }
        fn pod_index(&self, ip: &str) -> Vec<Arc<Pod>> {
            if ip != "10.240.0.1" {
                return Vec::new();
            }
            vec![Arc::new(Pod {
                pod_ips: vec!["10.240.0.1".into()],
                name: "client".into(),
                namespace: "podns".into(),
                ..Default::default()
            })]
        }
        fn ep_index(&self, _: &str) -> Vec<Arc<Endpoints>> {
            Vec::new()
        }
        fn ep_index_reverse(&self, _: &str) -> Vec<Arc<Endpoints>> {
            Vec::new()
        }
        fn namespace_exists(&self, _: &str) -> bool {
            true
        }
        fn has_synced(&self) -> bool {
            true
        }
        fn modified(&self) -> i64 {
            0
        }
        fn service_list(&self) -> Vec<Arc<Service>> {
            Vec::new()
        }
        fn endpoints_list(&self) -> Vec<Arc<Endpoints>> {
            Vec::new()
        }
    }

    fn query(name: &str, remote: &str) -> Request {
        let mut m = Message::new(1, MessageType::Query, OpCode::Query);
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        Request::new(
            m,
            "127.0.0.1:53".parse().unwrap(),
            remote.parse().unwrap(),
            Protocol::Udp,
        )
    }

    fn k8s(zones: &[&str], mode: PodMode) -> Kubernetes {
        let mut k = Kubernetes::new(zones.iter().map(|z| z.to_string()).collect());
        k.pod_mode = mode;
        k.auto_path_search = vec!["example.com.".into(), "internal.example.com.".into()];
        k.set_api(Arc::new(Fake));
        k
    }

    #[test]
    fn auto_path() {
        let k = k8s(&["cluster.local."], PodMode::Verified);
        assert_eq!(
            k.auto_path(&query("test.cluster.local.", "10.240.0.1:5353")),
            [
                "podns.svc.cluster.local.",
                "svc.cluster.local.",
                "cluster.local.",
                "example.com.",
                "internal.example.com.",
                ""
            ]
        );
        // not in the plugin's zones
        assert!(k.auto_path(&query("example.org.", "10.240.0.1:5353")).is_empty());
        // unknown client
        assert!(k.auto_path(&query("test.cluster.local.", "10.240.0.2:5353")).is_empty());

        // the root zone
        let k = k8s(&["."], PodMode::Verified);
        assert_eq!(
            k.auto_path(&query("test.", "10.240.0.1:5353")),
            ["podns.svc.", "svc.", ".", "example.com.", "internal.example.com.", ""]
        );

        // no pod cache without `pods verified`
        for mode in [PodMode::Disabled, PodMode::Insecure] {
            let k = k8s(&["cluster.local."], mode);
            assert!(k.auto_path(&query("test.cluster.local.", "10.240.0.1:5353")).is_empty());
        }
    }

    #[test]
    fn resolv_conf() {
        // whatever the host has; it must be normalized
        for s in search_from_resolv_conf() {
            assert!(s.ends_with('.'), "{s}");
            assert_eq!(s, s.to_ascii_lowercase());
        }
    }

    /// `autopath @kubernetes` in front of `kubernetes`, wired up the way
    /// the server does it.
    #[tokio::test]
    async fn autopath_kubernetes() {
        let corefile = "cluster.local:53 {\nautopath @kubernetes\nkubernetes cluster.local {\npods verified\n}\n}";
        let blocks = parse(corefile, "Corefile").unwrap();
        let mut cfg = BlockConfig::new(ZoneAddr::parse("cluster.local:53", "53").unwrap());
        let mut hooks = Hooks::default();
        let factories: [&dyn PluginFactory; 2] = [&kerndns_plugins::autopath::Setup, &Setup];
        for f in factories {
            let mut c = Controller::new(
                f.name(),
                Dispenser::new(blocks[0].tokens_for(f.name())),
                &mut cfg,
                &mut hooks,
                ".".into(),
            );
            f.setup(&mut c).unwrap();
        }
        BlockHandlers::fill(&mut cfg);
        // the kubernetes instance, with the fake API instead of a cluster
        assert!(AutoPathers::of(&mut cfg).get("kubernetes").is_some());
        let k = crate::external::slot(&mut cfg).get().unwrap().clone();
        k.set_api(Arc::new(Fake));
        // run only autopath's hook (kubernetes' would connect to an API)
        for (name, hook) in hooks.startup {
            if name == "autopath" {
                hook().unwrap();
            }
        }
        let chain = cfg.chain().unwrap();

        // svc1.testns, asked as the pod's resolver would with its search
        // path: svc1.testns.podns.svc.cluster.local.
        let mut ctx = Context::new("cluster.local.", "dns://:53");
        let mut w = CaptureWriter::new();
        let req = query("svc1.testns.podns.svc.cluster.local.", "10.240.0.1:5353");
        let rc = chain.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
        assert_eq!(rc, ResponseCode::NoError);
        let m = w.msg().unwrap();
        assert_eq!(m.queries[0].name().to_ascii(), "svc1.testns.podns.svc.cluster.local.");
        let got: Vec<String> = m.answers.iter().map(|r| r.to_string()).collect();
        assert_eq!(
            got,
            [
                "svc1.testns.podns.svc.cluster.local. 5 IN CNAME svc1.testns.svc.cluster.local.",
                "svc1.testns.svc.cluster.local. 5 IN A 10.0.0.1",
            ]
        );

        // a client that is no known pod: answered as asked
        let req = query("svc1.testns.podns.svc.cluster.local.", "10.240.0.9:5353");
        let mut w = CaptureWriter::new();
        chain.serve_dns(&mut ctx, &mut w, &req).await.unwrap();
        let m = w.msg().unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
        assert!(m.answers.is_empty());
    }
}
