//! `prometheus`: exports metrics over HTTP and counts the requests that
//! pass through it. Port of `plugin/metrics`.
//!
//! ```text
//! prometheus [ADDRESS]
//! ```

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

/// One endpoint per address, shared by all server blocks.
static ENDPOINTS: Mutex<Option<HashMap<String, Endpoint>>> = Mutex::new(None);

pub const DEFAULT_ADDR: &str = "localhost:9153";

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "prometheus"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut addr = DEFAULT_ADDR.to_string();
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
            if c.next_block() {
                let msg = format!("unknown property '{}'", c.val());
                return Err(c.errf(msg));
            }
        }

        let a2 = addr.clone();
        c.on_startup(move || {
            let mut eps = ENDPOINTS.lock().unwrap();
            let eps = eps.get_or_insert_with(HashMap::new);
            if eps.contains_key(&addr) {
                return Ok(());
            }
            let route: http::Route = Arc::new(|path, accept| match path {
                "/metrics" => {
                    let (ctype, body) = metrics::gather(accept);
                    (200, ctype, body)
                }
                _ => http::text(404, "404 page not found\n"),
            });
            // "localhost" binds the loopback address, like Go's listener
            let bind = addr.replacen("localhost:", "127.0.0.1:", 1);
            let ep = http::serve(&bind, route).map_err(|e| format!("listen tcp {addr}: {e}"))?;
            metrics::add_listen_addr(ep.addr.to_string());
            eps.insert(addr.clone(), ep);
            Ok(())
        });
        c.on_shutdown(move || {
            if let Some(eps) = ENDPOINTS.lock().unwrap().as_mut()
                && let Some(ep) = eps.remove(&a2)
            {
                ep.stop();
            }
        });

        let zones = Arc::new(c.server_block_keys());
        c.add_plugin(move |next| {
            Arc::new(Metrics {
                next,
                zones: zones.clone(),
            })
        });
        Ok(())
    }
}

pub struct Metrics {
    next: Next,
    zones: Arc<Vec<String>>,
}

#[async_trait]
impl Handler for Metrics {
    fn name(&self) -> &'static str {
        "prometheus"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let start = Instant::now();
        let zone = zones::matches(&self.zones, &req.name()).unwrap_or(".").to_string();
        let mut rec = Recorder::new(w);
        let res = next_or_failure("prometheus", &self.next, ctx, &mut rec, req).await;
        let status = result_rcode(&res);
        let rcode = if client_write(status) {
            rec.rcode.unwrap_or(status)
        } else {
            status
        };
        let view = ctx.view.clone().unwrap_or_default();
        report(&ctx.server, req, &zone, &view, rcode, "", rec.len, start);
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "prometheus"));
        assert!(setup_ok(&Setup, "prometheus localhost:9253"));
        assert!(setup_err(&Setup, "prometheus a b").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "prometheus\nprometheus").contains("only be used once"));
    }
}
