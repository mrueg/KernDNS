//! `health`: an HTTP endpoint that returns 200 OK while the process is
//! running. Port of `plugin/health`, with its self-probe metrics and
//! `lameduck` on the final shutdown only.
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
use crate::pluginmetrics as pm;

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

        // the endpoint and its self-probe
        type Running = Option<(Endpoint, tokio::task::JoinHandle<()>)>;
        let ep: Arc<Mutex<Running>> = Arc::default();
        let ep2 = ep.clone();
        c.on_startup(move || {
            let route: http::Route = Arc::new(|path, _| match path {
                "/health" => http::text(200, "OK"),
                _ => http::text(404, "404 page not found\n"),
            });
            let e = http::serve(&addr, route).map_err(|e| format!("listen tcp {addr}: {e}"))?;
            let probe = tokio::spawn(overloaded(addr.clone()));
            *ep.lock().unwrap() = Some((e, probe));
            Ok(())
        });
        // lameduck only when the process exits (`OnFinalShutdown`), not on
        // a reload, which just stops the endpoint (`OnRestart`)
        c.on_final_shutdown(move || {
            if !lameduck.is_zero() {
                kerndns_core::info!(
                    plugin = "health",
                    "Going into lameduck mode for {}",
                    format_duration(lameduck)
                );
                std::thread::sleep(lameduck);
            }
        });
        c.on_shutdown(move || {
            if let Some((e, probe)) = ep2.lock().unwrap().take() {
                probe.abort();
                e.stop();
            }
        });
        Ok(())
    }
}

/// The URL `overloaded` polls: `http://ADDR/health`, `localhost` for an
/// empty host.
fn probe_target(addr: &str) -> (String, String) {
    let (host, port) = addr.rsplit_once(':').unwrap_or((addr, "8080"));
    let host = if host.is_empty() { "localhost" } else { host };
    let connect = format!("{}:{port}", host);
    (connect, format!("http://{addr}/health"))
}

/// One GET of the health endpoint (`client.Do` with a 3 s timeout).
async fn probe(connect: &str, url: &str) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fut = async {
        let host = url.trim_start_matches("http://").trim_end_matches("/health");
        let mut s = tokio::net::TcpStream::connect(connect)
            .await
            .map_err(|e| e.to_string())?;
        let req = format!(
            "GET /health HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
        if !buf.starts_with(b"HTTP/") {
            return Err("malformed HTTP response".to_string());
        }
        Ok(())
    };
    match tokio::time::timeout(Duration::from_secs(3), fut).await {
        Ok(r) => r,
        Err(_) => Err("context deadline exceeded (Client.Timeout exceeded while awaiting headers)".into()),
    }
}

/// Poll the health endpoint every second and export how long it took
/// (`coredns_health_request_duration_seconds`) and how often it failed
/// (`coredns_health_request_failures_total`), like CoreDNS's `overloaded`.
async fn overloaded(addr: String) {
    let (connect, url) = probe_target(&addr);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await;
    loop {
        tick.tick().await;
        let start = std::time::Instant::now();
        let res = probe(&connect, &url).await;
        let elapsed = start.elapsed();
        pm::HEALTH_DURATION.observe(elapsed.as_secs_f64());
        match res {
            Err(e) => {
                pm::HEALTH_FAILURES.inc();
                kerndns_core::warning!(plugin = "health", "Local health request to {url:?} failed: {e}");
            }
            Ok(()) if elapsed > Duration::from_secs(1) => {
                kerndns_core::warning!(
                    plugin = "health",
                    "Local health request to {url:?} took more than 1s: {}",
                    format_duration(elapsed)
                );
            }
            Ok(()) => {}
        }
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

    #[test]
    fn probe_targets() {
        assert_eq!(
            probe_target(":8080"),
            ("localhost:8080".into(), "http://:8080/health".into())
        );
        assert_eq!(
            probe_target("[::1]:8081"),
            ("[::1]:8081".into(), "http://[::1]:8081/health".into())
        );
    }

    /// The self-probe succeeds against a health endpoint and fails when
    /// nothing listens.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn self_probe() {
        let route: http::Route = Arc::new(|_, _| http::text(200, "OK"));
        let ep = http::serve("127.0.0.1:0", route).unwrap();
        let addr = ep.addr.to_string();
        let (connect, url) = probe_target(&addr);
        probe(&connect, &url).await.unwrap();
        tokio::task::spawn_blocking(move || ep.stop()).await.unwrap();
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let (connect, url) = probe_target(&closed.to_string());
        assert!(probe(&connect, &url).await.is_err());
    }
}
