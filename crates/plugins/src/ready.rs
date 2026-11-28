//! `ready`: an HTTP endpoint that returns 200 once every plugin that can be
//! not-ready reports ready. Port of `plugin/ready`.
//!
//! ```text
//! ready [ADDRESS] {
//!     monitor until-ready|continuously
//! }
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kerndns_core::{Controller, PluginFactory, SetupError, readiness};

use crate::http::{self, Endpoint};

/// One endpoint per address, shared by all server blocks (`uniq.New`).
/// The endpoint and its "not shutting down" flag.
type Running = (Endpoint, Arc<AtomicBool>);
/// `None` marks an address whose listener failed to start: CoreDNS's
/// `uniq.ForEach` drops that error without a log line, and the address
/// stays "done" so a reload does not try it again.
static ENDPOINTS: Mutex<Option<HashMap<String, Option<Running>>>> = Mutex::new(None);

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "ready"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut addr = ":8181".to_string();
        let mut continuously = false;
        let mut seen = false;
        while c.next() {
            if seen {
                return Err(SetupError::new(
                    "ready",
                    "this plugin can only be used once per Server Block",
                ));
            }
            seen = true;
            let args = c.remaining_args();
            match args.len() {
                0 => {}
                1 => {
                    http::split_host_port(&args[0]).map_err(|e| SetupError::new("ready", e))?;
                    addr = args[0].clone();
                }
                _ => return Err(c.arg_err()),
            }
            while c.next_block() {
                match c.val() {
                    "monitor" => {
                        let a = c.remaining_args();
                        if a.len() != 1 {
                            return Err(c.arg_err());
                        }
                        continuously = match a[0].as_str() {
                            "until-ready" => false,
                            "continuously" => true,
                            other => {
                                let msg = format!("monitor type '{other}' not supported");
                                return Err(c.errf(msg));
                            }
                        };
                    }
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
        }
        readiness::set_monitor_continuously(continuously);

        let a2 = addr.clone();
        c.on_startup(move || {
            let mut eps = ENDPOINTS.lock().unwrap();
            let eps = eps.get_or_insert_with(HashMap::new);
            if eps.contains_key(&addr) {
                return Ok(());
            }
            let up = Arc::new(AtomicBool::new(true));
            let up2 = up.clone();
            let route: http::Route = Arc::new(move |path, _| {
                if path != "/ready" {
                    return http::text(404, "404 page not found\n");
                }
                if !up2.load(Ordering::Relaxed) {
                    return http::text(503, "Shutting down");
                }
                let (ok, not_ready) = readiness::ready();
                if ok {
                    return http::text(200, "OK");
                }
                let list = not_ready.join(",");
                kerndns_core::info!(plugin = "ready", "Plugins not ready: {list:?}");
                http::text(503, list)
            });
            let ep = http::serve(&addr, route).ok();
            eps.insert(addr.clone(), ep.map(|ep| (ep, up)));
            Ok(())
        });
        c.on_shutdown(move || {
            // a failed address stays (CoreDNS's onFinalShutdown skips it)
            if let Some(eps) = ENDPOINTS.lock().unwrap().as_mut()
                && eps.get(&a2).is_some_and(Option::is_some)
                && let Some(Some((ep, up))) = eps.remove(&a2)
            {
                up.store(false, Ordering::Relaxed);
                ep.stop();
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "ready"));
        assert!(setup_ok(&Setup, "ready :8182 {\n monitor continuously\n}"));
        assert!(setup_err(&Setup, "ready {\n monitor sometimes\n}").contains("not supported"));
        assert!(setup_err(&Setup, "ready\nready").contains("only be used once"));
    }
}
