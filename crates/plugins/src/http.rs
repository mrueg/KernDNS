//! A minimal HTTP/1.1 server for the `health`, `ready` and `prometheus`
//! endpoints.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// Maps a request path and its `Accept` header to (status, content type, body).
pub type Route = Arc<dyn Fn(&str, &str) -> (u16, String, Vec<u8>) + Send + Sync>;

/// A plain-text response.
pub fn text(status: u16, body: impl Into<String>) -> (u16, String, Vec<u8>) {
    (status, "text/plain; charset=utf-8".into(), body.into().into_bytes())
}

/// A running endpoint; dropping it does not stop it, call [`Endpoint::stop`].
pub struct Endpoint {
    pub addr: SocketAddr,
    task: tokio::task::AbortHandle,
    /// Disconnects once the accept loop, and with it the listener, is gone.
    closed: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Endpoint {
    /// Stop serving and close the listener before returning (waiting up to
    /// a second), so the address can be bound again right away, e.g. by the
    /// next configuration on reload. Call it off the async workers: it
    /// blocks while a worker drops the aborted task.
    pub fn stop(&self) {
        self.task.abort();
        let _ = self
            .closed
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(1));
    }
}

/// Turn Go-style `host:port` (`:8080` means all interfaces) into a socket address string.
pub fn listen_addr(addr: &str) -> String {
    if let Some(port) = addr.strip_prefix(':') {
        format!("[::]:{port}")
    } else {
        addr.to_string()
    }
}

/// Check `host:port` like Go's `net.SplitHostPort`.
pub fn split_host_port(addr: &str) -> Result<(), String> {
    let Some(i) = addr.rfind(':') else {
        return Err(format!("address {addr}: missing port in address"));
    };
    let host = &addr[..i];
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return Err(format!("address {addr}: too many colons in address"));
    }
    Ok(())
}

/// Bind `addr` (falling back from `[::]` to `0.0.0.0`) and serve `route`.
pub fn serve(addr: &str, route: Route) -> std::io::Result<Endpoint> {
    let addr = listen_addr(addr);
    let std_listener = match std::net::TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) if addr.starts_with("[::]") => {
            std::net::TcpListener::bind(addr.replacen("[::]", "0.0.0.0", 1)).map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };
    std_listener.set_nonblocking(true)?;
    let local = std_listener.local_addr()?;
    let listener = TcpListener::from_std(std_listener)?;
    let (closed_tx, closed) = std::sync::mpsc::channel::<()>();
    // fields drop in order: the listener is closed before the sender goes
    struct Owned {
        listener: TcpListener,
        _closed: std::sync::mpsc::Sender<()>,
    }
    let owned = Owned {
        listener,
        _closed: closed_tx,
    };
    let task = tokio::spawn(async move {
        let owned = owned;
        loop {
            let Ok((stream, _)) = owned.listener.accept().await else {
                continue;
            };
            let route = route.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let accept = req.headers().get("accept").and_then(|v| v.to_str().ok()).unwrap_or("");
                    let (status, ctype, body) = route(req.uri().path(), accept);
                    let resp = Response::builder()
                        .status(status)
                        .header("Content-Type", ctype)
                        .body(Full::new(Bytes::from(body)))
                        .expect("valid response");
                    async move { Ok::<_, Infallible>(resp) }
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    Ok(Endpoint {
        addr: local,
        task: task.abort_handle(),
        closed: Mutex::new(closed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ready`, `health` and `prometheus` stop their endpoint in a shutdown
    /// hook and bind the same address again in the next configuration's
    /// startup hook right after: on reload the port must already be free,
    /// as it is once CoreDNS has closed its listener.
    #[test]
    fn stop_releases_the_port() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let route: Route = Arc::new(|_, _| text(200, "OK"));
        let mut ep = rt.block_on(async { serve("127.0.0.1:0", route.clone()) }).unwrap();
        for _ in 0..100 {
            let addr = ep.addr;
            ep.stop();
            ep = rt
                .block_on(async { serve(&addr.to_string(), route.clone()) })
                .unwrap_or_else(|e| panic!("bind {addr} after stop: {e}"));
        }
        ep.stop();
    }
}
