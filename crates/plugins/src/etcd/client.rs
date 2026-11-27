//! A small etcd v3 client with only the calls the etcd plugin makes:
//! `KV.Range` (a key or a prefix), `Lease.LeaseTimeToLive` and
//! `Auth.Authenticate`. gRPC runs on hyper's HTTP/2 client (the `grpc`
//! plugin's response handling) and the protobuf messages are written by
//! hand, so the build needs neither protoc nor tonic.
//!
//! Like `clientv3`: endpoints are `http://HOST:PORT` (cleartext),
//! `https://HOST:PORT` (TLS), `unix://PATH`/`unixs://PATH`, or a bare
//! `HOST:PORT` (TLS when the `tls` option is set). Requests are spread over
//! the endpoints round robin, and an endpoint that cannot be reached is
//! skipped for the next one. Each endpoint keeps one HTTP/2 connection,
//! dialed on first use and again when it breaks. With credentials, a token
//! from `Authenticate` goes with every call, and is fetched again when etcd
//! says it is invalid or stale.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use http_body_util::Full;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use kerndns_core::async_trait;
use kerndns_core::protobuf::{Field, next_field, put_bytes_field, put_varint_field};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

use crate::grpc::client::read_unary;
pub use crate::grpc::client::{Code, RpcError};

const RANGE: &str = "/etcdserverpb.KV/Range";
const LEASE_TTL: &str = "/etcdserverpb.Lease/LeaseTimeToLive";
const AUTHENTICATE: &str = "/etcdserverpb.Auth/Authenticate";

/// clientv3's `MaxCallRecvMsgSize` default (`math.MaxInt32`).
const MAX_RECV: usize = i32::MAX as usize;

const UNAUTHENTICATED: Code = Code(16);
const INVALID_ARGUMENT: Code = Code(3);

/// One key from a range, like `mvccpb.KeyValue`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyValue {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    pub lease: i64,
}

/// `RangeResponse`: the keys and how many matched.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeResponse {
    pub kvs: Vec<KeyValue>,
    pub count: i64,
}

/// What the plugin needs from etcd; tests use an in-memory store.
#[async_trait]
pub trait Kv: Send + Sync {
    /// `Get(key)`, or `Get(key, WithPrefix())`.
    async fn get(&self, key: &str, prefix: bool, deadline: Instant) -> Result<RangeResponse, RpcError>;

    /// `TimeToLive(lease)`: the lease's remaining TTL in seconds.
    async fn lease_ttl(&self, lease: i64, deadline: Instant) -> Result<i64, RpcError>;
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

type Sender = SendRequest<Full<Bytes>>;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Tcp(String),
    Unix(PathBuf),
}

struct Endpoint {
    target: Target,
    tls: Option<(Arc<ClientConfig>, ServerName<'static>)>,
    /// `scheme://authority` of every request.
    base: String,
    conn: tokio::sync::Mutex<Option<Sender>>,
}

impl Endpoint {
    /// `endpoint.Interpret`: where to dial and whether to use TLS.
    fn parse(ep: &str, tls: Option<&Arc<ClientConfig>>) -> Result<Endpoint, String> {
        let (scheme, rest) = match ep.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => match ep.split_once(':') {
                Some((s @ ("unix" | "unixs"), r)) => (s.to_string(), r),
                _ => (String::new(), ep),
            },
        };
        let secure = match scheme.as_str() {
            "http" | "unix" => false,
            "https" | "unixs" => true,
            _ => tls.is_some(),
        };
        let tls_config = |host: &str| -> Result<Option<(Arc<ClientConfig>, ServerName<'static>)>, String> {
            if !secure {
                return Ok(None);
            }
            let cfg = match tls {
                Some(c) => c.clone(),
                None => crate::tlsconfig::client_config(&[])?,
            };
            let mut cfg = (*cfg).clone();
            cfg.alpn_protocols = vec![b"h2".to_vec()];
            let name = ServerName::try_from(host.to_string()).map_err(|e| format!("invalid endpoint {ep:?}: {e}"))?;
            Ok(Some((Arc::new(cfg), name)))
        };
        let http = if secure { "https" } else { "http" };
        if scheme.starts_with("unix") {
            return Ok(Endpoint {
                target: Target::Unix(PathBuf::from(rest)),
                tls: tls_config("localhost")?,
                base: format!("{http}://localhost"),
                conn: tokio::sync::Mutex::new(None),
            });
        }
        // the authority: anything after it (a path) is ignored
        let authority = rest.split('/').next().unwrap_or_default();
        let host = match authority.rsplit_once(':') {
            Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => authority,
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        Ok(Endpoint {
            target: Target::Tcp(authority.to_string()),
            tls: tls_config(host)?,
            base: format!("{http}://{authority}"),
            conn: tokio::sync::Mutex::new(None),
        })
    }

    async fn dial(&self) -> Result<Sender, RpcError> {
        let unavailable = |e: &dyn std::fmt::Display| {
            RpcError::new(
                Code::UNAVAILABLE,
                format!("connection error: desc = \"transport: Error while dialing: {e}\""),
            )
        };
        let io: Box<dyn Io> = match &self.target {
            Target::Tcp(a) => {
                let s = TcpStream::connect(a.as_str()).await.map_err(|e| unavailable(&e))?;
                let _ = s.set_nodelay(true);
                Box::new(s)
            }
            Target::Unix(p) => Box::new(UnixStream::connect(p).await.map_err(|e| unavailable(&e))?),
        };
        let io: Box<dyn Io> = match &self.tls {
            None => io,
            Some((cfg, name)) => {
                let c = tokio_rustls::TlsConnector::from(cfg.clone());
                Box::new(c.connect(name.clone(), io).await.map_err(|e| {
                    RpcError::new(
                        Code::UNAVAILABLE,
                        format!("connection error: desc = \"transport: authentication handshake failed: {e}\""),
                    )
                })?)
            }
        };
        let (send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(TokioIo::new(io))
            .await
            .map_err(|e| unavailable(&e))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(send)
    }

    async fn sender(&self) -> Result<Sender, RpcError> {
        let mut c = self.conn.lock().await;
        if let Some(s) = c.as_ref()
            && !s.is_closed()
        {
            return Ok(s.clone());
        }
        let s = self.dial().await?;
        *c = Some(s.clone());
        Ok(s)
    }

    async fn unary(
        &self,
        method: &str,
        pb: &[u8],
        deadline: Instant,
        token: Option<&str>,
    ) -> Result<Vec<u8>, RpcError> {
        let mut send = self.sender().await?;
        let mut frame = BytesMut::with_capacity(pb.len() + 5);
        frame.extend_from_slice(&[0]);
        frame.extend_from_slice(&(pb.len() as u32).to_be_bytes());
        frame.extend_from_slice(pb);
        let timeout = deadline.saturating_duration_since(Instant::now());
        let mut req = hyper::Request::post(format!("{}{method}", self.base))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("user-agent", concat!("kerndns-etcd/", env!("CARGO_PKG_VERSION")))
            .header("grpc-timeout", format!("{}u", timeout.as_micros().clamp(1, 99_999_999)));
        if let Some(t) = token {
            req = req.header("token", t);
        }
        let req = req
            .body(Full::new(frame.freeze()))
            .map_err(|e| RpcError::new(Code::INTERNAL, e.to_string()))?;
        send.ready()
            .await
            .map_err(|e| RpcError::new(Code::UNAVAILABLE, format!("connection error: desc = \"{e}\"")))?;
        let resp = send
            .send_request(req)
            .await
            .map_err(|e| RpcError::new(Code::UNAVAILABLE, format!("error reading from server: {e}")))?;
        read_unary(resp, MAX_RECV).await
    }
}

/// An etcd v3 client (`clientv3.Client` for the calls above).
pub struct Client {
    endpoints: Vec<Endpoint>,
    next: AtomicUsize,
    credentials: Option<(String, String)>,
    /// The auth token; `Some("")` when etcd has auth disabled.
    token: std::sync::Mutex<Option<String>>,
}

impl Client {
    /// Endpoints are only checked here; connections are made on first use.
    pub fn new(
        endpoints: &[String],
        tls: Option<Arc<ClientConfig>>,
        credentials: Option<(String, String)>,
    ) -> Result<Client, String> {
        if endpoints.is_empty() {
            return Err("etcdclient: no available endpoints".into());
        }
        let endpoints = endpoints
            .iter()
            .map(|e| Endpoint::parse(e, tls.as_ref()))
            .collect::<Result<_, _>>()?;
        Ok(Client {
            endpoints,
            next: AtomicUsize::new(0),
            credentials,
            token: std::sync::Mutex::new(None),
        })
    }

    async fn token(&self, ep: &Endpoint, deadline: Instant) -> Result<Option<String>, RpcError> {
        let Some((user, pass)) = &self.credentials else {
            return Ok(None);
        };
        if let Some(t) = self.token.lock().unwrap().clone() {
            return Ok(Some(t).filter(|t| !t.is_empty()));
        }
        let mut pb = Vec::new();
        put_bytes_field(&mut pb, 1, user.as_bytes());
        put_bytes_field(&mut pb, 2, pass.as_bytes());
        let t = match ep.unary(AUTHENTICATE, &pb, deadline, None).await {
            Ok(resp) => decode_token(&resp)?,
            Err(e) if e.msg == "etcdserver: authentication is not enabled" => String::new(),
            Err(e) => return Err(e),
        };
        *self.token.lock().unwrap() = Some(t.clone());
        Ok(Some(t).filter(|t| !t.is_empty()))
    }

    async fn call_on(&self, ep: &Endpoint, method: &str, pb: &[u8], deadline: Instant) -> Result<Vec<u8>, RpcError> {
        let token = self.token(ep, deadline).await?;
        match ep.unary(method, pb, deadline, token.as_deref()).await {
            Err(e) if self.credentials.is_some() && stale_token(&e) => {
                *self.token.lock().unwrap() = None;
                let token = self.token(ep, deadline).await?;
                ep.unary(method, pb, deadline, token.as_deref()).await
            }
            r => r,
        }
    }

    async fn call(&self, method: &str, pb: &[u8], deadline: Instant) -> Result<Vec<u8>, RpcError> {
        let fut = async {
            let n = self.endpoints.len();
            let start = self.next.fetch_add(1, Ordering::Relaxed);
            let mut last = None;
            for i in 0..n {
                let ep = &self.endpoints[(start + i) % n];
                match self.call_on(ep, method, pb, deadline).await {
                    Err(e) if e.code == Code::UNAVAILABLE => last = Some(e),
                    r => return r,
                }
            }
            Err(last.expect("at least one endpoint"))
        };
        match tokio::time::timeout_at(deadline.into(), fut).await {
            Ok(r) => r,
            Err(_) => Err(RpcError::new(Code::DEADLINE_EXCEEDED, "context deadline exceeded")),
        }
    }
}

/// clientv3 fetches a new token for these.
fn stale_token(e: &RpcError) -> bool {
    (e.code == UNAUTHENTICATED && e.msg == "etcdserver: invalid auth token")
        || (e.code == INVALID_ARGUMENT && e.msg == "etcdserver: revision of auth store is old")
}

fn bad_message(what: &str) -> RpcError {
    RpcError::new(
        Code::INTERNAL,
        format!(
            "grpc: failed to unmarshal the received message: proto: cannot parse invalid wire-format data ({what})"
        ),
    )
}

/// `clientv3.GetPrefixRangeEnd`.
pub fn prefix_range_end(key: &[u8]) -> Vec<u8> {
    let mut end = key.to_vec();
    while let Some(last) = end.last_mut() {
        if *last < 0xff {
            *last += 1;
            return end;
        }
        end.pop();
    }
    vec![0]
}

pub fn encode_range(key: &str, prefix: bool) -> Vec<u8> {
    let mut pb = Vec::new();
    put_bytes_field(&mut pb, 1, key.as_bytes());
    if prefix {
        put_bytes_field(&mut pb, 2, &prefix_range_end(key.as_bytes()));
    }
    pb
}

pub fn decode_range(mut b: &[u8]) -> Option<RangeResponse> {
    let mut r = RangeResponse::default();
    while !b.is_empty() {
        match next_field(&mut b)? {
            (2, Field::Bytes(kv)) => r.kvs.push(decode_kv(kv)?),
            (4, Field::Varint(n)) => r.count = n as i64,
            _ => {}
        }
    }
    Some(r)
}

fn decode_kv(mut b: &[u8]) -> Option<KeyValue> {
    let mut kv = KeyValue::default();
    while !b.is_empty() {
        match next_field(&mut b)? {
            (1, Field::Bytes(k)) => kv.key = k.to_vec(),
            (5, Field::Bytes(v)) => kv.value = v.to_vec(),
            (6, Field::Varint(l)) => kv.lease = l as i64,
            _ => {}
        }
    }
    Some(kv)
}

fn decode_ttl(mut b: &[u8]) -> Option<i64> {
    let mut ttl = 0;
    while !b.is_empty() {
        if let (3, Field::Varint(t)) = next_field(&mut b)? {
            ttl = t as i64;
        }
    }
    Some(ttl)
}

fn decode_token(mut b: &[u8]) -> Result<String, RpcError> {
    let mut token = String::new();
    while !b.is_empty() {
        if let (2, Field::Bytes(t)) = next_field(&mut b).ok_or_else(|| bad_message("AuthenticateResponse"))? {
            token = String::from_utf8_lossy(t).into_owned();
        }
    }
    Ok(token)
}

#[async_trait]
impl Kv for Client {
    async fn get(&self, key: &str, prefix: bool, deadline: Instant) -> Result<RangeResponse, RpcError> {
        let resp = self.call(RANGE, &encode_range(key, prefix), deadline).await?;
        decode_range(&resp).ok_or_else(|| bad_message("RangeResponse"))
    }

    async fn lease_ttl(&self, lease: i64, deadline: Instant) -> Result<i64, RpcError> {
        let mut pb = Vec::new();
        put_varint_field(&mut pb, 1, lease as u64);
        let resp = self.call(LEASE_TTL, &pb, deadline).await?;
        decode_ttl(&resp).ok_or_else(|| bad_message("LeaseTimeToLiveResponse"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_end() {
        assert_eq!(prefix_range_end(b"/skydns/"), b"/skydns0");
        assert_eq!(prefix_range_end(b"a\xff"), b"b");
        assert_eq!(prefix_range_end(b"\xff\xff"), b"\0");
    }

    #[test]
    fn range_messages() {
        assert_eq!(encode_range("ab", false), b"\x0a\x02ab");
        assert_eq!(encode_range("ab", true), b"\x0a\x02ab\x12\x02ac");
        // header, one kv (key, create_revision, value, lease), more, count
        let kv = b"\x0a\x01k\x10\x05\x2a\x01v\x30\x96\x01";
        let mut resp = b"\x0a\x00".to_vec();
        resp.push(0x12);
        resp.push(kv.len() as u8);
        resp.extend_from_slice(kv);
        resp.extend_from_slice(b"\x18\x00\x20\x01");
        let r = decode_range(&resp).unwrap();
        assert_eq!(r.count, 1);
        assert_eq!(
            r.kvs,
            vec![KeyValue {
                key: b"k".to_vec(),
                value: b"v".to_vec(),
                lease: 150
            }]
        );
        assert!(decode_range(b"\x12\x05ab").is_none());
        assert_eq!(decode_ttl(b"\x10\x07\x18\x3c").unwrap(), 60);
        assert_eq!(decode_token(b"\x12\x03abc").unwrap(), "abc");
    }

    #[test]
    fn endpoints() {
        let ep = |s: &str| Endpoint::parse(s, None).unwrap();
        let e = ep("http://localhost:2379");
        assert_eq!(e.target, Target::Tcp("localhost:2379".into()));
        assert_eq!(e.base, "http://localhost:2379");
        assert!(e.tls.is_none());
        let e = ep("localhost:300");
        assert_eq!(e.target, Target::Tcp("localhost:300".into()));
        assert!(e.tls.is_none());
        let e = ep("https://[::1]:2379/");
        assert_eq!(e.target, Target::Tcp("[::1]:2379".into()));
        assert!(e.tls.is_some());
        assert_eq!(
            ep("unix:///run/etcd.sock").target,
            Target::Unix("/run/etcd.sock".into())
        );
        assert_eq!(ep("unix:etcd.sock").target, Target::Unix("etcd.sock".into()));
        // a bare address uses TLS when the tls option is set
        let cfg = crate::tlsconfig::client_config(&[]).unwrap();
        assert!(Endpoint::parse("127.0.0.1:2379", Some(&cfg)).unwrap().tls.is_some());
        assert!(
            Endpoint::parse("http://127.0.0.1:2379", Some(&cfg))
                .unwrap()
                .tls
                .is_none()
        );
    }
}
