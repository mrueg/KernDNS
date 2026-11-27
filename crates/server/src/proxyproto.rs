//! PROXY protocol on the listeners (`proxyproto`): UDP datagrams carry a
//! v2 header in front of the DNS message (CoreDNS's
//! `plugin/pkg/proxyproto.PacketConn`), TCP connections start with a v1 or
//! v2 header (`go-proxyproto`'s `Listener`). The client address plugins see
//! is the header's source; responses still go to the proxy.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use kerndns_core::proxyproto::{
    Header, Parsed, Policy, ProxyProtoConfig, READ_HEADER_TIMEOUT, UDP_SESSION_MAX_ENTRIES, parse, parse_eof,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// A socket address as Go prints it (IPv4-mapped addresses as IPv4).
pub fn canonical(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}

/// What a datagram turned into.
#[derive(Debug, PartialEq, Eq)]
pub struct Datagram {
    /// Where the DNS message starts.
    pub offset: usize,
    /// The client the plugins see.
    pub client: SocketAddr,
    pub tlvs: Option<Arc<[u8]>>,
}

struct Session {
    header: Arc<Header>,
    last: Instant,
}

/// The UDP side: header stripping and Spectrum-style session tracking.
pub struct UdpProxy {
    cfg: Arc<ProxyProtoConfig>,
    sessions: Mutex<HashMap<SocketAddr, Session>>,
}

impl UdpProxy {
    pub fn new(cfg: Arc<ProxyProtoConfig>) -> Self {
        UdpProxy {
            cfg,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn tlvs(&self, h: &Header) -> Option<Arc<[u8]>> {
        if !self.cfg.tlv_metadata {
            return None;
        }
        h.raw_tlvs().map(Arc::from)
    }

    fn ttl(&self) -> Option<Duration> {
        self.cfg.udp_session_ttl.filter(|d| !d.is_zero())
    }

    fn store_session(&self, peer: SocketAddr, header: Arc<Header>, ttl: Duration) {
        let cap = match self.cfg.udp_max_sessions {
            0 => UDP_SESSION_MAX_ENTRIES,
            n => n,
        };
        let now = Instant::now();
        let mut s = self.sessions.lock().unwrap();
        s.retain(|_, v| now.duration_since(v.last) < ttl);
        if s.len() >= cap
            && !s.contains_key(&peer)
            && let Some(oldest) = s.iter().min_by_key(|(_, v)| v.last).map(|(k, _)| *k)
        {
            s.remove(&oldest);
        }
        s.insert(peer, Session { header, last: now });
    }

    fn lookup_session(&self, peer: SocketAddr, ttl: Duration) -> Option<Arc<Header>> {
        let now = Instant::now();
        let mut s = self.sessions.lock().unwrap();
        let e = s.get_mut(&peer)?;
        if now.duration_since(e.last) >= ttl {
            s.remove(&peer);
            return None;
        }
        // looking a session up refreshes it
        e.last = now;
        Some(e.header.clone())
    }

    /// `PacketConn.readFrom`: `Ok(None)` for a header-only datagram that
    /// only opened a session; an error means the datagram is dropped.
    pub fn read(&self, packet: &[u8], peer: SocketAddr) -> Result<Option<Datagram>, String> {
        let policy = self.cfg.policy(peer.ip());
        let mut d = Datagram {
            offset: 0,
            client: peer,
            tlvs: None,
        };
        if policy == Policy::Skip {
            return Ok(Some(d));
        }
        let header = match parse_eof(packet) {
            Parsed::NoHeader | Parsed::Incomplete => None,
            Parsed::Error(e) => {
                return Err(format!(
                    "parsing Proxy Protocol header (packet size: {}): {e}",
                    packet.len()
                ));
            }
            Parsed::Header(h, n) => {
                if h.version != 2 {
                    return Err(format!(
                        "unsupported Proxy Protocol version {} (only v2 supported for UDP)",
                        h.version
                    ));
                }
                if !h.is_udp() {
                    return Err(format!(
                        "PROXY Protocol header is not UDP type (transport protocol: 0x{:x})",
                        h.transport
                    ));
                }
                d.offset = n;
                Some(Arc::new(h))
            }
        };
        match policy {
            Policy::Reject if header.is_some() => {
                return Err("connection rejected by Proxy Protocol connection policy".into());
            }
            Policy::Use => match &header {
                Some(h) => {
                    if !h.local
                        && let Some(src) = h.source
                    {
                        d.client = src;
                        d.tlvs = self.tlvs(h);
                        if let Some(ttl) = self.ttl() {
                            self.store_session(peer, h.clone(), ttl);
                        }
                    }
                    if self.ttl().is_some() && d.offset == packet.len() {
                        return Ok(None);
                    }
                }
                None => {
                    if let Some(ttl) = self.ttl()
                        && let Some(h) = self.lookup_session(peer, ttl)
                        && let Some(src) = h.source
                    {
                        d.client = src;
                        d.tlvs = self.tlvs(&h);
                    }
                }
            },
            _ => {}
        }
        Ok(Some(d))
    }
}

/// A stream with bytes already read off it put back in front.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Prefixed { prefix, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let pos = self.pos;
            buf.put_slice(&self.prefix[pos..pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A TCP connection after its PROXY header.
pub struct Accepted<S> {
    pub stream: Prefixed<S>,
    pub client: SocketAddr,
    /// The header's destination, when its source is used.
    pub local: Option<SocketAddr>,
    pub tlvs: Option<Arc<[u8]>>,
}

/// Read a TCP connection's PROXY header (`proxyproto.Conn`'s first read).
/// `None` means the connection must be closed: the header is invalid, or
/// the policy rejects it. A connection that sends nothing in time counts
/// as having no header, like go-proxyproto.
pub async fn accept<S: AsyncRead + Unpin>(
    cfg: &ProxyProtoConfig,
    mut stream: S,
    peer: SocketAddr,
    timeout: Duration,
) -> Option<Accepted<S>> {
    let policy = cfg.policy(peer.ip());
    if policy == Policy::Skip {
        return Some(Accepted {
            stream: Prefixed::new(Vec::new(), stream),
            client: peer,
            local: None,
            tlvs: None,
        });
    }
    let mut buf = Vec::with_capacity(256);
    let deadline = tokio::time::Instant::now() + timeout.min(READ_HEADER_TIMEOUT);
    let mut chunk = [0u8; 256];
    let parsed = loop {
        match parse(&buf) {
            Parsed::Incomplete => {}
            p => break p,
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Err(_) => break Parsed::NoHeader,
            Ok(Ok(0)) => break parse_eof(&buf),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => return None,
        }
    };
    let mut accepted = Accepted {
        stream: Prefixed::new(Vec::new(), stream),
        client: peer,
        local: None,
        tlvs: None,
    };
    match parsed {
        Parsed::Error(e) => {
            kerndns_core::debug!(plugin = "proxyproto", "{}: {e}", canonical(peer));
            None
        }
        Parsed::NoHeader | Parsed::Incomplete => {
            accepted.stream.prefix = buf;
            Some(accepted)
        }
        Parsed::Header(h, n) => {
            if policy == Policy::Reject {
                return None;
            }
            accepted.stream.prefix = buf.split_off(n);
            if policy == Policy::Use
                && !h.local
                && let Some(src) = h.source
            {
                accepted.client = src;
                accepted.local = h.destination;
                if cfg.tlv_metadata {
                    accepted.tlvs = h.raw_tlvs().map(Arc::from);
                }
            }
            Some(accepted)
        }
    }
}

/// [`accept`] when the listener has PROXY protocol, for the DoH and gRPC
/// listeners: the stream and the client address (TLVs are not passed on
/// there).
pub async fn maybe_accept<S: AsyncRead + Unpin>(
    cfg: Option<&ProxyProtoConfig>,
    stream: S,
    peer: SocketAddr,
) -> Option<(Prefixed<S>, SocketAddr)> {
    match cfg {
        None => Some((Prefixed::new(Vec::new(), stream), peer)),
        Some(c) => accept(c, stream, peer, READ_HEADER_TIMEOUT)
            .await
            .map(|a| (a.stream, a.client)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    const SIG: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

    fn v2_udp(src: [u8; 4], port: u16, tlvs: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut body = src.to_vec();
        body.extend_from_slice(&[10, 0, 0, 1]);
        body.extend_from_slice(&port.to_be_bytes());
        body.extend_from_slice(&53u16.to_be_bytes());
        body.extend_from_slice(tlvs);
        let mut b = SIG.to_vec();
        b.extend_from_slice(&[0x21, 0x12]);
        b.extend_from_slice(&(body.len() as u16).to_be_bytes());
        b.extend_from_slice(&body);
        b.extend_from_slice(payload);
        b
    }

    fn proxy(f: impl FnOnce(&mut ProxyProtoConfig)) -> UdpProxy {
        let mut c = ProxyProtoConfig::default();
        f(&mut c);
        UdpProxy::new(Arc::new(c))
    }

    fn peer() -> SocketAddr {
        "192.168.1.1:5000".parse().unwrap()
    }

    #[test]
    fn udp_use_ignore_reject_skip() {
        let pkt = v2_udp([192, 0, 2, 7], 4242, &[], b"dns");
        let d = proxy(|_| {}).read(&pkt, peer()).unwrap().unwrap();
        assert_eq!(d.client, "192.0.2.7:4242".parse().unwrap());
        assert_eq!(&pkt[d.offset..], b"dns");

        let ignore = proxy(|c| c.default_set = true);
        let d = ignore.read(&pkt, peer()).unwrap().unwrap();
        assert_eq!((d.client, &pkt[d.offset..]), (peer(), &b"dns"[..]));

        let reject = proxy(|c| {
            c.default_set = true;
            c.default = Policy::Reject;
        });
        assert_eq!(
            reject.read(&pkt, peer()).unwrap_err(),
            "connection rejected by Proxy Protocol connection policy"
        );
        // a datagram without a header is fine under reject
        assert_eq!(reject.read(b"dns", peer()).unwrap().unwrap().offset, 0);

        let skip = proxy(|c| {
            c.default_set = true;
            c.default = Policy::Skip;
        });
        assert_eq!(skip.read(&pkt, peer()).unwrap().unwrap().offset, 0);
    }

    #[test]
    fn udp_rejects_v1_and_tcp_headers() {
        let p = proxy(|_| {});
        assert_eq!(
            p.read(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\nx", peer()).unwrap_err(),
            "unsupported Proxy Protocol version 1 (only v2 supported for UDP)"
        );
        let mut tcp = v2_udp([1, 2, 3, 4], 1, &[], b"");
        tcp[13] = 0x11;
        assert_eq!(
            p.read(&tcp, peer()).unwrap_err(),
            "PROXY Protocol header is not UDP type (transport protocol: 0x11)"
        );
        let mut bad = v2_udp([1, 2, 3, 4], 1, &[], b"");
        bad[12] = 0x22;
        assert_eq!(
            p.read(&bad, peer()).unwrap_err(),
            format!(
                "parsing Proxy Protocol header (packet size: {}): proxyproto: unsupported proxy protocol version and command",
                bad.len()
            )
        );
    }

    #[test]
    fn udp_session_tracking() {
        let p = proxy(|c| {
            c.udp_session_ttl = Some(Duration::from_secs(30));
            c.tlv_metadata = true;
        });
        // header-only datagram opens the session
        let hdr = v2_udp([192, 0, 2, 9], 53000, &[0xe1, 0, 1, 7], b"");
        assert_eq!(p.read(&hdr, peer()), Ok(None));
        let d = p.read(b"dns", peer()).unwrap().unwrap();
        assert_eq!(d.client, "192.0.2.9:53000".parse().unwrap());
        assert_eq!(d.tlvs.as_deref(), Some(&[0xe1, 0, 1, 7][..]));
        // another peer has no session
        let other: SocketAddr = "192.168.1.2:5000".parse().unwrap();
        assert_eq!(p.read(b"dns", other).unwrap().unwrap().client, other);
    }

    #[test]
    fn udp_session_cap() {
        let p = proxy(|c| {
            c.udp_session_ttl = Some(Duration::from_secs(30));
            c.udp_max_sessions = 1;
        });
        let a: SocketAddr = "192.168.1.1:1".parse().unwrap();
        let b: SocketAddr = "192.168.1.1:2".parse().unwrap();
        p.read(&v2_udp([192, 0, 2, 1], 1, &[], b""), a).unwrap();
        p.read(&v2_udp([192, 0, 2, 2], 1, &[], b""), b).unwrap();
        assert_eq!(p.read(b"x", a).unwrap().unwrap().client, a, "evicted");
        assert_ne!(p.read(b"x", b).unwrap().unwrap().client, b);
    }

    async fn tcp(cfg: ProxyProtoConfig, send: &[u8]) -> Option<(SocketAddr, Vec<u8>, Option<Arc<[u8]>>)> {
        let (mut a, b) = tokio::io::duplex(1024);
        a.write_all(send).await.unwrap();
        drop(a);
        let acc = accept(&cfg, b, peer(), Duration::from_secs(1)).await?;
        let mut s = acc.stream;
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).await.unwrap();
        Some((acc.client, rest, acc.tlvs))
    }

    #[tokio::test]
    async fn tcp_headers() {
        let (client, rest, _) = tcp(
            ProxyProtoConfig::default(),
            b"PROXY TCP4 192.0.2.1 10.0.0.1 12345 53\r\n\x00\x02ab",
        )
        .await
        .unwrap();
        assert_eq!(client, "192.0.2.1:12345".parse().unwrap());
        assert_eq!(rest, b"\x00\x02ab");
        // no header: everything is kept
        let (client, rest, _) = tcp(ProxyProtoConfig::default(), b"\x00\x02ab").await.unwrap();
        assert_eq!((client, rest.as_slice()), (peer(), &b"\x00\x02ab"[..]));
        // a broken header closes the connection
        assert!(tcp(ProxyProtoConfig::default(), b"PROXY TCP4 x\r\n").await.is_none());
        // reject closes connections with a header
        let reject = ProxyProtoConfig {
            default: Policy::Reject,
            default_set: true,
            ..Default::default()
        };
        assert!(tcp(reject, b"PROXY UNKNOWN\r\n").await.is_none());
        // v2 with TLVs
        let mut v2 = v2_udp([192, 0, 2, 5], 99, &[0xe0, 0, 1, 1], b"\x00\x01z");
        v2[13] = 0x11;
        let cfg = ProxyProtoConfig {
            tlv_metadata: true,
            ..Default::default()
        };
        let (client, rest, tlvs) = tcp(cfg, &v2).await.unwrap();
        assert_eq!(client, "192.0.2.5:99".parse().unwrap());
        assert_eq!(rest, b"\x00\x01z");
        assert_eq!(tlvs.as_deref(), Some(&[0xe0, 0, 1, 1][..]));
    }
}
