//! `prometheus`: exports metrics over HTTP and counts the requests that
//! pass through it. Port of `plugin/metrics`.
//!
//! ```text
//! prometheus [ADDRESS] {
//!     runtime_metrics
//!     tls WEB_CONFIG_FILE
//! }
//! ```
//!
//! `tls` serves the endpoint as configured by a Prometheus web config file
//! (HTTPS, client certificates, basic auth, headers, a rate limit); see
//! [`crate::webconfig`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use kerndns_core::metrics::{self, report};
use kerndns_core::zones;
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Recorder, Request, ResponseWriter, SetupError,
    async_trait, client_write, next_or_failure, result_rcode,
};

use crate::http::{self, Endpoint};

/// One endpoint per address, shared by all server blocks (`None`: its web
/// config was invalid, nothing serves the address until the next load).
static ENDPOINTS: Mutex<Option<HashMap<String, Option<Endpoint>>>> = Mutex::new(None);

pub const DEFAULT_ADDR: &str = "localhost:9153";

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "prometheus"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        crate::pluginmetrics::register_process_wide();
        let mut addr = DEFAULT_ADDR.to_string();
        let mut tls_config = String::new();
        let mut seen = false;
        while c.next() {
            if seen {
                return Err(SetupError::new(
                    "prometheus",
                    "this plugin can only be used once per Server Block",
                ));
            }
            seen = true;
            let args = c.remaining_args();
            match args.len() {
                0 => {}
                1 => {
                    http::split_host_port(&args[0]).map_err(|e| SetupError::new("prometheus", e))?;
                    addr = args[0].clone();
                }
                _ => return Err(c.arg_err()),
            }
            while c.next_block() {
                match c.val() {
                    // Go runtime metrics: there is no Go runtime to report
                    // on, so accept the option like CoreDNS and say so
                    "runtime_metrics" => {
                        if !c.remaining_args().is_empty() {
                            return Err(c.arg_err());
                        }
                        kerndns_core::warning!(
                            plugin = "prometheus",
                            "runtime_metrics has no effect: KernDNS has no Go runtime to report on"
                        );
                    }
                    "tls" => {
                        if !tls_config.is_empty() {
                            return Err(c.errf("tls block already specified"));
                        }
                        let args = c.remaining_args();
                        if args.len() != 1 {
                            return Err(c.arg_err());
                        }
                        tls_config = args[0].clone();
                    }
                    other => {
                        let msg = format!("unknown option: {other}");
                        return Err(c.errf(msg));
                    }
                }
            }
        }

        let a2 = addr.clone();
        c.on_startup(move || {
            let mut eps = ENDPOINTS.lock().unwrap();
            let eps = eps.get_or_insert_with(HashMap::new);
            if eps.contains_key(&addr) {
                return Ok(());
            }
            // The web config is checked before the address is taken. Like
            // CoreDNS (whose `uniq.ForEach` drops the startup error), an
            // invalid one is logged and the server runs without the
            // endpoint.
            let web = if tls_config.is_empty() {
                None
            } else {
                match crate::webconfig::Web::new(&tls_config) {
                    Ok(w) => Some(Arc::new(w)),
                    Err(e) => {
                        kerndns_core::error!("{}", e);
                        eps.insert(addr.clone(), None);
                        return Ok(());
                    }
                }
            };
            let route: http::Route = Arc::new(|path, accept| match path {
                "/metrics" => {
                    let (ctype, body) = metrics::gather(accept);
                    (200, ctype, body)
                }
                _ => http::text(404, "404 page not found\n"),
            });
            // "localhost" binds the loopback address, like Go's listener
            let bind = addr.replacen("localhost:", "127.0.0.1:", 1);
            let ep = http::serve_web(&bind, route, web).map_err(|e| format!("listen tcp {addr}: {e}"))?;
            metrics::add_listen_addr(ep.addr.to_string());
            eps.insert(addr.clone(), Some(ep));
            Ok(())
        });
        c.on_shutdown(move || {
            if let Some(eps) = ENDPOINTS.lock().unwrap().as_mut()
                && let Some(Some(ep)) = eps.remove(&a2)
            {
                ep.stop();
            }
        });

        let zones = ZoneNames::of(c.config);
        for k in c.server_block_keys() {
            zones.add(&k);
        }
        c.add_plugin(move |next| {
            Arc::new(Metrics {
                next,
                zones: zones.clone(),
            })
        });
        Ok(())
    }
}

/// The zones a block's `prometheus` labels requests with: the server block
/// keys plus what other plugins add at run time (`Metrics.AddZone` and
/// `RemoveZone`, used by `auto`).
#[derive(Clone, Default)]
pub struct ZoneNames(Arc<arc_swap::ArcSwap<Vec<String>>>);

impl ZoneNames {
    /// The zone names of this block (created on first use).
    pub fn of(cfg: &mut kerndns_core::BlockConfig) -> ZoneNames {
        if cfg.extensions.get::<ZoneNames>().is_none() {
            cfg.extensions.insert(ZoneNames::default());
        }
        cfg.extensions.get::<ZoneNames>().cloned().expect("inserted above")
    }

    pub fn add(&self, zone: &str) {
        self.0.rcu(|z| {
            let mut z = (**z).clone();
            if !z.iter().any(|n| n == zone) {
                z.push(zone.to_string());
            }
            z
        });
    }

    pub fn remove(&self, zone: &str) {
        self.0
            .rcu(|z| z.iter().filter(|n| *n != zone).cloned().collect::<Vec<_>>());
    }

    pub fn names(&self) -> Arc<Vec<String>> {
        self.0.load_full()
    }
}

pub struct Metrics {
    next: Next,
    zones: ZoneNames,
}

#[async_trait]
impl Handler for Metrics {
    fn name(&self) -> &'static str {
        "prometheus"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let start = Instant::now();
        let zone = zones::matches(&self.zones.0.load(), &req.name())
            .unwrap_or(".")
            .to_string();
        let mut rec = Recorder::rcode_only(w);
        let res = next_or_failure("prometheus", &self.next, ctx, &mut rec, req).await;
        let status = result_rcode(&res);
        let rcode = if client_write(status) {
            rec.rcode.unwrap_or(status)
        } else {
            status
        };
        let plugin = writer_plugin(&self.next, rec.rcode.is_some());
        let view = ctx.view.clone().unwrap_or_default();
        // reported once the server has encoded the response, with its size
        let (server, req) = (ctx.server.clone(), req.clone());
        ctx.on_sent.push(Arc::new(move |size| {
            report(&server, &req, &zone, &view, rcode, plugin, size, start)
        }));
        res
    }
}

/// The `plugin` label of `coredns_dns_responses_total`: the plugin that
/// wrote the response, as CoreDNS reports it.
///
/// CoreDNS's `plugin.NextOrFailure` wraps the writer it passes on in a
/// `pluginWriter` named after the next plugin, which tags the writer it
/// wraps on a write only if that writer is the metrics `Recorder`
/// (`PluginTracker`). Only `prometheus`'s own `NextOrFailure` wraps the
/// recorder directly, so every response that reaches it is tagged with the
/// plugin right after `prometheus` in the chain, whichever plugin further
/// down actually wrote it (`errors` in `prometheus; errors; forward`).
/// Nothing written (the server writes the error response): empty.
fn writer_plugin(next: &Next, written: bool) -> &'static str {
    match next {
        Some(h) if written => h.name(),
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::CaptureWriter;
    use kerndns_core::proto::op::ResponseCode;
    use kerndns_core::proto::rr::RecordType;

    /// A plugin that calls `next` (wrapping the writer, like `cache` or
    /// `log` do) or, with no next, answers with `rcode`.
    struct Pass {
        name: &'static str,
        next: Next,
        rcode: ResponseCode,
    }

    #[async_trait]
    impl Handler for Pass {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
            if self.next.is_some() {
                let mut rec = Recorder::new(w);
                return next_or_failure(self.name, &self.next, ctx, &mut rec, req).await;
            }
            if client_write(self.rcode) {
                let _ = w.write_msg(req.error_reply(self.rcode)).await;
                return Ok(self.rcode);
            }
            Err(kerndns_core::PluginError::new(self.name, self.rcode, "failed"))
        }
    }

    fn pass(name: &'static str, next: Next, rcode: ResponseCode) -> Next {
        Some(Arc::new(Pass { name, next, rcode }))
    }

    /// Serve one query through `prometheus` in front of `next` and return
    /// the label set that `coredns_dns_responses_total` counted it under.
    async fn counted(server: &str, next: Next) -> (String, String) {
        let m = Metrics {
            next,
            zones: ZoneNames::default(),
        };
        let mut ctx = Context::new(".", server);
        let mut w = CaptureWriter::new();
        let _ = m
            .serve_dns(&mut ctx, &mut w, &query("example.org.", RecordType::A, "10.0.0.1:53"))
            .await;
        for hook in &ctx.on_sent {
            hook(0);
        }
        let mut found = Vec::new();
        for f in prometheus::gather() {
            if f.name() != "coredns_dns_responses_total" {
                continue;
            }
            for m in f.get_metric() {
                let l: HashMap<_, _> = m.get_label().iter().map(|l| (l.name(), l.value())).collect();
                if l["server"] == server {
                    found.push((l["plugin"].to_string(), l["rcode"].to_string()));
                }
            }
        }
        assert_eq!(found.len(), 1, "{found:?}");
        found.remove(0)
    }

    #[tokio::test]
    async fn plugin_label() {
        let nx = ResponseCode::NXDomain;
        // the plugin after prometheus wrote it
        let next = pass("whoami", None, ResponseCode::NoError);
        assert_eq!(counted("dns://:1", next).await, ("whoami".into(), "NOERROR".into()));
        // written further down the chain: still the plugin after prometheus,
        // like CoreDNS (`prometheus; errors; log; whoami` counts "errors")
        let next = pass("errors", pass("log", pass("template", None, nx), nx), nx);
        assert_eq!(counted("dns://:2", next).await, ("errors".into(), "NXDOMAIN".into()));
        // nothing written (the server writes the SERVFAIL): no plugin
        let next = pass("cache", pass("forward", None, ResponseCode::ServFail), nx);
        assert_eq!(counted("dns://:3", next).await, (String::new(), "SERVFAIL".into()));
        // no next plugin
        assert_eq!(counted("dns://:4", None).await, (String::new(), "SERVFAIL".into()));
    }

    #[test]
    fn writer_plugin_needs_a_write() {
        let next = pass("whoami", None, ResponseCode::NoError);
        assert_eq!(writer_plugin(&next, true), "whoami");
        assert_eq!(writer_plugin(&next, false), "");
        assert_eq!(writer_plugin(&None, true), "");
    }

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "prometheus"));
        assert!(setup_ok(&Setup, "prometheus localhost:9253"));
        assert!(setup_err(&Setup, "prometheus a b").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "prometheus\nprometheus").contains("only be used once"));
        // CoreDNS 1.15: Go runtime metrics, accepted (no effect)
        assert!(setup_ok(&Setup, "prometheus {\n runtime_metrics\n}"));
        assert!(setup_err(&Setup, "prometheus {\n runtime_metrics x\n}").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "prometheus {\n bogus\n}").contains("unknown option: bogus"));
        // CoreDNS 1.15: a Prometheus web config file
        assert!(setup_ok(&Setup, "prometheus {\n tls web.yml\n}"));
        assert!(setup_err(&Setup, "prometheus {\n tls\n}").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "prometheus {\n tls a b\n}").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "prometheus {\n tls a\n tls b\n}").contains("tls block already specified"));
    }
}
