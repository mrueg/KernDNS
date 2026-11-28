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

/// Turn Go-style `host:port` (`:8080` means all interfaces, an empty port
/// any free one, as for Go's `net.Listen`) into a socket address string.
pub fn listen_addr(addr: &str) -> String {
    let mut a = if let Some(port) = addr.strip_prefix(':') {
        format!("[::]:{port}")
    } else {
        addr.to_string()
    };
    if a.ends_with(':') {
        a.push('0');
    }
    a
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

/// Bind `addr` with `SO_REUSEPORT` like CoreDNS's `reuseport.Listen`, so
/// several server blocks (or a reloaded configuration) can listen on the
/// same address.
fn bind_reuseport(addr: &str) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    use std::net::ToSocketAddrs;
    let mut last = std::io::Error::new(std::io::ErrorKind::InvalidInput, "no addresses");
    for sa in addr.to_socket_addrs()? {
        let res = (|| {
            let s = Socket::new(Domain::for_address(sa), Type::STREAM, None)?;
            if sa.is_ipv6() {
                // dual stack, like Go's ":8080"
                let _ = s.set_only_v6(false);
            }
            s.set_reuse_address(true)?;
            s.set_reuse_port(true)?;
            s.bind(&sa.into())?;
            s.listen(1024)?;
            Ok::<_, std::io::Error>(std::net::TcpListener::from(s))
        })();
        match res {
            Ok(l) => return Ok(l),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Bind `addr` (falling back from `[::]` to `0.0.0.0`) and serve `route`.
pub fn serve(addr: &str, route: Route) -> std::io::Result<Endpoint> {
    let addr = listen_addr(addr);
    let std_listener = match bind_reuseport(&addr) {
        Ok(l) => l,
        Err(e) if addr.starts_with("[::]") => bind_reuseport(&addr.replacen("[::]", "0.0.0.0", 1)).map_err(|_| e)?,
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

    /// CoreDNS's metrics README has `prometheus localhost:{$PORT}`, which
    /// is `localhost:` with $PORT unset: Go listens on a free port then.
    #[test]
    fn empty_port_is_any_port() {
        assert_eq!(listen_addr(":9153"), "[::]:9153");
        assert_eq!(listen_addr(":"), "[::]:0");
        assert_eq!(listen_addr("localhost:"), "localhost:0");
        assert_eq!(listen_addr("127.0.0.1:8080"), "127.0.0.1:8080");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let route: Route = Arc::new(|_, _| text(200, "OK"));
        let ep = rt.block_on(async { serve("localhost:", route) }).unwrap();
        assert_ne!(ep.addr.port(), 0);
        ep.stop();
    }
}
