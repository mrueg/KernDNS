//! `health`: an HTTP endpoint that returns 200 OK while the process is
//! running. Port of `plugin/health` (without the self-probe metrics).
//!
//! ```text
//! health [ADDRESS] {
//!     lameduck DURATION
//! }
//! ```

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kerndns_core::duration::{format_duration, parse_duration};
use kerndns_core::{Controller, PluginFactory, SetupError};

use crate::http::{self, Endpoint};

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "health"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut addr = String::new();
        let mut lameduck = Duration::ZERO;
        while c.next() {
            let args = c.remaining_args();
            match args.len() {
                0 => {}
                1 => {
                    http::split_host_port(&args[0]).map_err(|e| SetupError::new("health", e))?;
                    addr = args[0].clone();
                }
                _ => return Err(c.arg_err()),
            }
            while c.next_block() {
                match c.val() {
                    "lameduck" => {
                        let a = c.remaining_args();
                        if a.len() != 1 {
                            return Err(c.arg_err());
                        }
                        lameduck = parse_duration(&a[0]).map_err(|e| {
                            SetupError::new(
                                "health",
                                format!("unable to parse lameduck duration value: '{}' : {e}", a[0]),
                            )
                        })?;
                    }
                    other => {
                        let msg = format!("unknown property '{other}'");
                        return Err(c.errf(msg));
                    }
                }
            }
        }
        if addr.is_empty() {
            addr = ":8080".into();
        }

        let ep: Arc<Mutex<Option<Endpoint>>> = Arc::default();
        let ep2 = ep.clone();
        c.on_startup(move || {
            let route: http::Route = Arc::new(|path, _| match path {
                "/health" => http::text(200, "OK"),
                _ => http::text(404, "404 page not found\n"),
            });
            let e = http::serve(&addr, route).map_err(|e| format!("listen tcp {addr}: {e}"))?;
            *ep.lock().unwrap() = Some(e);
            Ok(())
        });
        c.on_shutdown(move || {
            if !lameduck.is_zero() {
                kerndns_core::info!(
                    plugin = "health",
                    "Going into lameduck mode for {}",
                    format_duration(lameduck)
                );
                std::thread::sleep(lameduck);
            }
            if let Some(e) = ep2.lock().unwrap().take() {
                e.stop();
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
        assert!(setup_ok(&Setup, "health"));
        assert!(setup_ok(&Setup, "health :8081 {\n lameduck 5s\n}"));
        assert!(setup_err(&Setup, "health a b").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "health localhost").contains("missing port"));
        assert!(setup_err(&Setup, "health {\n lameduck x\n}").contains("unable to parse lameduck"));
    }
}
