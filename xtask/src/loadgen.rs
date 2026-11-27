//! `cargo xtask loadgen`: a small DNS load generator for the transports
//! dnsperf can't drive: DoQ (RFC 9250), DoH over HTTP/3 and CoreDNS's
//! gRPC `DnsService`.
//!
//! It takes dnsperf's main arguments and prints dnsperf's statistics block
//! (plus latency percentiles), so `cargo xtask bench` runs it in place of
//! dnsperf for cases with `# dnsperf: -m doq`, `-m doh3` or `-m grpc`.
//!
//! ```text
//! cargo xtask loadgen -m doq|doh3|grpc [-s 127.0.0.1] -p PORT -d QUERYFILE
//!     [-c CLIENTS] [-T THREADS] [-q OUTSTANDING] [-l SECONDS] [-Q QPS]
//!     [-t TIMEOUT] [--ca PEM] [--tls] [--path /dns-query]
//! ```
//!
//! `-c` connections share `-q` outstanding queries (closed loop: each
//! slot sends its next query when the previous one is answered or times
//! out); `-Q` paces them to a fixed rate. DoQ and DoH3 verify the server
//! against `--ca` (default `bench/shared/tls/ca.pem`, whose certificate
//! covers 127.0.0.1 and `kerndns.test`); gRPC is cleartext HTTP/2 unless
//! `--tls`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_core::protobuf::{decode_packet, encode_packet};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};

/// The transport under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Doq,
    Doh3,
    Grpc,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "doq" => Some(Mode::Doq),
            "doh3" => Some(Mode::Doh3),
            "grpc" => Some(Mode::Grpc),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Mode::Doq => "doq",
            Mode::Doh3 => "doh3",
            Mode::Grpc => "grpc",
        }
    }
}

#[derive(Debug, Clone)]
struct Opts {
    mode: Mode,
    server: IpAddr,
    port: u16,
    queries: PathBuf,
    clients: usize,
    threads: usize,
    outstanding: usize,
    secs: f64,
    rate: Option<f64>,
    timeout: Duration,
    ca: PathBuf,
    tls: bool,
    path: String,
}

fn parse_args(args: &[String]) -> Result<Opts> {
    let mut o = Opts {
        mode: Mode::Doq,
        server: IpAddr::from([127, 0, 0, 1]),
        port: 0,
        queries: PathBuf::new(),
        clients: 1,
        threads: 1,
        outstanding: 100,
        secs: 10.0,
        rate: None,
        timeout: Duration::from_secs(5),
        ca: crate::root().join("bench/shared/tls/ca.pem"),
        tls: false,
        path: "/dns-query".into(),
    };
    let mut mode = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().with_context(|| format!("{a} needs a value"));
        match a.as_str() {
            "-m" => {
                let m = val()?;
                mode = Some(Mode::parse(m).with_context(|| format!("-m {m}: expected doq, doh3 or grpc"))?);
            }
            "-s" => o.server = val()?.parse().context("-s needs an IP address")?,
            "-p" => o.port = val()?.parse()?,
            "-d" => o.queries = PathBuf::from(val()?),
            "-c" => o.clients = val()?.parse::<usize>()?.max(1),
            "-T" => o.threads = val()?.parse::<usize>()?.max(1),
            "-q" => o.outstanding = val()?.parse::<usize>()?.max(1),
            "-l" => o.secs = val()?.parse()?,
            "-Q" => o.rate = Some(val()?.parse::<f64>()?).filter(|r| *r > 0.0),
            "-t" => o.timeout = Duration::from_secs_f64(val()?.parse()?),
            "--ca" => o.ca = PathBuf::from(val()?),
            "--tls" => o.tls = true,
            "--path" => o.path = val()?.clone(),
            other => bail!("loadgen: unknown argument {other}"),
        }
    }
    o.mode = mode.context("loadgen: -m doq|doh3|grpc is required")?;
    if o.port == 0 {
        bail!("loadgen: -p PORT is required");
    }
    if o.queries.as_os_str().is_empty() {
        bail!("loadgen: -d QUERYFILE is required");
    }
    Ok(o)
}

/// Queries from a dnsperf input file (`name TYPE` per line), packed with
/// ID 0 (RFC 9250 requires it for DoQ, RFC 8484 recommends it for DoH).
fn read_queries(path: &PathBuf) -> Result<Vec<Bytes>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let mut f = line.split_whitespace();
        let name = f.next().unwrap_or_default();
        let ty = f.next().unwrap_or("A");
        out.push(Bytes::from(pack_query(name, ty)?));
    }
    if out.is_empty() {
        bail!("{}: no queries", path.display());
    }
    Ok(out)
}

fn pack_query(name: &str, ty: &str) -> Result<Vec<u8>> {
    let mut m = Message::new(0, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    let rt = RecordType::from_str(&ty.to_ascii_uppercase()).map_err(|e| anyhow::anyhow!("type {ty}: {e}"))?;
    m.add_query(Query::query(Name::from_ascii(name)?, rt));
    Ok(m.to_vec()?)
}

fn tls_config(ca: &PathBuf, alpn: &[u8]) -> Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(ca).with_context(|| format!("reading {}", ca.display()))? {
        roots.add(c?)?;
    }
    let mut c = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![alpn.to_vec()];
    Ok(c)
}

/// One connection to the server, cheap to clone across the query slots
/// that share it.
#[derive(Clone)]
enum Conn {
    Doq(quinn::Connection),
    Doh3(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, Arc<str>),
    Grpc(hyper::client::conn::http2::SendRequest<Full<Bytes>>, Arc<str>),
}

/// Keeps the endpoint or the connection's driver task alive.
enum Keep {
    Endpoint(#[allow(dead_code)] quinn::Endpoint),
    Task(#[allow(dead_code)] tokio::task::AbortHandle),
}

async fn quic_connect(o: &Opts, alpn: &[u8]) -> Result<(quinn::Connection, quinn::Endpoint)> {
    let bind: SocketAddr = if o.server.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let mut ep = quinn::Endpoint::client(bind)?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config(&o.ca, alpn)?)?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
    cfg.transport_config(Arc::new(transport));
    ep.set_default_client_config(cfg);
    let conn = ep
        .connect(SocketAddr::new(o.server, o.port), &o.server.to_string())?
        .await
        .context("QUIC handshake")?;
    Ok((conn, ep))
}

async fn connect(o: &Opts) -> Result<(Conn, Keep)> {
    let authority: Arc<str> = Arc::from(SocketAddr::new(o.server, o.port).to_string());
    match o.mode {
        Mode::Doq => {
            let (conn, ep) = quic_connect(o, b"doq").await?;
            Ok((Conn::Doq(conn), Keep::Endpoint(ep)))
        }
        Mode::Doh3 => {
            let (conn, ep) = quic_connect(o, b"h3").await?;
            let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn)).await?;
            // the endpoint lives as long as the driver task
            let task = tokio::spawn(async move {
                let _ep = ep;
                std::future::poll_fn(|cx| driver.poll_close(cx)).await
            });
            Ok((Conn::Doh3(send, authority), Keep::Task(task.abort_handle())))
        }
        Mode::Grpc => {
            let tcp = tokio::net::TcpStream::connect(SocketAddr::new(o.server, o.port)).await?;
            tcp.set_nodelay(true)?;
            let mut b = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
            b.max_concurrent_reset_streams(0);
            let (send, task) = if o.tls {
                let c = tokio_rustls::TlsConnector::from(Arc::new(tls_config(&o.ca, b"h2")?));
                let s = c.connect(ServerName::from(o.server), tcp).await?;
                let (send, conn) = b.handshake(TokioIo::new(s)).await?;
                (send, tokio::spawn(async move { drop(conn.await) }))
            } else {
                let (send, conn) = b.handshake(TokioIo::new(tcp)).await?;
                (send, tokio::spawn(async move { drop(conn.await) }))
            };
            Ok((Conn::Grpc(send, authority), Keep::Task(task.abort_handle())))
        }
    }
}

/// Send one query and return the response message.
async fn exchange(conn: &mut Conn, o: &Opts, q: &Bytes) -> Result<Vec<u8>> {
    match conn {
        Conn::Doq(c) => {
            let (mut send, mut recv) = c.open_bi().await?;
            let mut out = Vec::with_capacity(q.len() + 2);
            out.extend_from_slice(&(q.len() as u16).to_be_bytes());
            out.extend_from_slice(q);
            send.write_all(&out).await?;
            send.finish()?;
            let all = recv.read_to_end(65537).await?;
            if all.len() < 2 || u16::from_be_bytes([all[0], all[1]]) as usize != all.len() - 2 {
                bail!("bad DoQ answer framing");
            }
            Ok(all[2..].to_vec())
        }
        Conn::Doh3(send, authority) => {
            let req = http::Request::post(format!("https://{authority}{}", o.path))
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(())?;
            let mut stream = send.send_request(req).await?;
            stream.send_data(q.clone()).await?;
            stream.finish().await?;
            let resp = stream.recv_response().await?;
            if !resp.status().is_success() {
                bail!("HTTP status {}", resp.status());
            }
            let mut out = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await? {
                while chunk.has_remaining() {
                    let c = chunk.chunk();
                    out.extend_from_slice(c);
                    let n = c.len();
                    chunk.advance(n);
                }
            }
            Ok(out)
        }
        Conn::Grpc(send, authority) => {
            let pb = encode_packet(q);
            let mut frame = Vec::with_capacity(pb.len() + 5);
            frame.push(0);
            frame.extend_from_slice(&(pb.len() as u32).to_be_bytes());
            frame.extend_from_slice(&pb);
            let scheme = if o.tls { "https" } else { "http" };
            let req = hyper::Request::post(format!("{scheme}://{authority}/coredns.dns.DnsService/Query"))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(Full::new(Bytes::from(frame)))?;
            send.ready().await?;
            let resp = send.send_request(req).await?;
            let status = resp.headers().get("grpc-status").cloned();
            let body = resp.into_body().collect().await?;
            let trailer = body.trailers().and_then(|t| t.get("grpc-status")).cloned();
            if let Some(s) = status.or(trailer).filter(|s| s.as_bytes() != b"0") {
                bail!("grpc-status {s:?}");
            }
            let b = body.to_bytes();
            if b.len() < 5 || b[0] != 0 {
                bail!("bad gRPC frame");
            }
            let n = u32::from_be_bytes([b[1], b[2], b[3], b[4]]) as usize;
            let msg = b.get(5..5 + n).context("short gRPC frame")?;
            decode_packet(msg).context("bad DnsPacket")
        }
    }
}

fn rcode_name(wire: &[u8]) -> String {
    match wire.get(3).map(|b| b & 0xF) {
        Some(0) => "NOERROR".into(),
        Some(1) => "FORMERR".into(),
        Some(2) => "SERVFAIL".into(),
        Some(3) => "NXDOMAIN".into(),
        Some(4) => "NOTIMP".into(),
        Some(5) => "REFUSED".into(),
        Some(n) => format!("RCODE{n}"),
        None => "SHORT".into(),
    }
}

#[derive(Default)]
struct Stats {
    sent: u64,
    lost: u64,
    /// Latencies of answered queries, in µs.
    lat: Vec<u32>,
    rcodes: BTreeMap<String, u64>,
    /// First few errors, for the report.
    errors: BTreeMap<String, u64>,
}

impl Stats {
    fn merge(&mut self, o: Stats) {
        self.sent += o.sent;
        self.lost += o.lost;
        self.lat.extend(o.lat);
        for (k, v) in o.rcodes {
            *self.rcodes.entry(k).or_default() += v;
        }
        for (k, v) in o.errors {
            *self.errors.entry(k).or_default() += v;
        }
    }
}

/// One query slot: sends queries back to back (or at its share of the
/// rate) until the deadline.
async fn slot(
    mut conn: Conn,
    o: Arc<Opts>,
    queries: Arc<Vec<Bytes>>,
    next: Arc<AtomicUsize>,
    start: tokio::time::Instant,
    deadline: tokio::time::Instant,
) -> Stats {
    let mut st = Stats::default();
    loop {
        let i = next.fetch_add(1, Ordering::Relaxed);
        if let Some(rate) = o.rate {
            // query i is due at start + i/rate
            let due = start + Duration::from_secs_f64(i as f64 / rate);
            if due >= deadline {
                break;
            }
            tokio::time::sleep_until(due).await;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let q = &queries[i % queries.len()];
        st.sent += 1;
        match tokio::time::timeout(o.timeout, exchange(&mut conn, &o, q)).await {
            Ok(Ok(resp)) => {
                st.lat.push(now.elapsed().as_micros().min(u32::MAX as u128) as u32);
                *st.rcodes.entry(rcode_name(&resp)).or_default() += 1;
            }
            Ok(Err(e)) => {
                st.lost += 1;
                *st.errors.entry(format!("{e:#}")).or_default() += 1;
            }
            Err(_) => {
                st.lost += 1;
                *st.errors.entry("timeout".into()).or_default() += 1;
            }
        }
    }
    st
}

async fn run_async(o: Opts) -> Result<(Stats, f64)> {
    let queries = Arc::new(read_queries(&o.queries)?);
    let o = Arc::new(o);
    let mut conns = Vec::new();
    for _ in 0..o.clients {
        conns.push(
            connect(&o)
                .await
                .with_context(|| format!("connecting to {}:{} ({})", o.server, o.port, o.mode.name()))?,
        );
    }
    let next = Arc::new(AtomicUsize::new(0));
    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs_f64(o.secs);
    let mut tasks = tokio::task::JoinSet::new();
    for s in 0..o.outstanding.max(o.clients) {
        let conn = conns[s % conns.len()].0.clone();
        tasks.spawn(slot(conn, o.clone(), queries.clone(), next.clone(), start, deadline));
    }
    let mut st = Stats::default();
    while let Some(r) = tasks.join_next().await {
        st.merge(r?);
    }
    let elapsed = start.elapsed().as_secs_f64();
    for (c, _) in &conns {
        if let Conn::Doq(c) = c {
            c.close(0u32.into(), b"");
        }
    }
    Ok((st, elapsed))
}

fn pct(sorted: &[u32], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() as f64 * p / 100.0).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[i] as f64 / 1e6
}

/// dnsperf's statistics block, which `bench` parses.
fn report(o: &Opts, mut st: Stats, elapsed: f64) -> String {
    use std::fmt::Write as _;
    let completed = st.sent - st.lost;
    let share = |n: u64| {
        if st.sent == 0 {
            0.0
        } else {
            n as f64 * 100.0 / st.sent as f64
        }
    };
    st.lat.sort_unstable();
    let n = st.lat.len().max(1) as f64;
    let avg = st.lat.iter().map(|&l| l as f64).sum::<f64>() / n / 1e6;
    let var = st.lat.iter().map(|&l| (l as f64 / 1e6 - avg).powi(2)).sum::<f64>() / n;
    let min = st.lat.first().copied().unwrap_or(0) as f64 / 1e6;
    let max = st.lat.last().copied().unwrap_or(0) as f64 / 1e6;
    let rcodes = st
        .rcodes
        .iter()
        .map(|(k, v)| format!("{k} {v} ({:.2}%)", *v as f64 * 100.0 / completed.max(1) as f64))
        .collect::<Vec<_>>()
        .join(", ");
    let mut s = String::new();
    let _ = writeln!(s, "DNS load generator (cargo xtask loadgen, {})\n", o.mode.name());
    let _ = writeln!(s, "Statistics:\n");
    let _ = writeln!(s, "  Queries sent:         {}", st.sent);
    let _ = writeln!(s, "  Queries completed:    {completed} ({:.2}%)", share(completed));
    let _ = writeln!(s, "  Queries lost:         {} ({:.2}%)\n", st.lost, share(st.lost));
    let _ = writeln!(s, "  Response codes:       {rcodes}");
    let _ = writeln!(s, "  Run time (s):         {elapsed:.6}");
    let _ = writeln!(
        s,
        "  Queries per second:   {:.6}\n",
        completed as f64 / elapsed.max(1e-9)
    );
    let _ = writeln!(s, "  Average Latency (s):  {avg:.6} (min {min:.6}, max {max:.6})");
    let _ = writeln!(s, "  Latency StdDev (s):   {:.6}", var.sqrt());
    let _ = writeln!(
        s,
        "  Latency percentiles (s): p50 {:.6}, p90 {:.6}, p99 {:.6}, p99.9 {:.6}",
        pct(&st.lat, 50.0),
        pct(&st.lat, 90.0),
        pct(&st.lat, 99.0),
        pct(&st.lat, 99.9)
    );
    if !st.errors.is_empty() {
        let _ = writeln!(s, "\nErrors:");
        for (e, n) in st.errors.iter().take(5) {
            let _ = writeln!(s, "  {n} x {e}");
        }
    }
    s
}

pub fn run(args: &[String]) -> Result<()> {
    let o = parse_args(args)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(o.threads)
        .enable_all()
        .build()?;
    let (st, elapsed) = rt.block_on(run_async(o.clone()))?;
    print!("{}", report(&o, st, elapsed));
    rt.shutdown_timeout(Duration::from_millis(100));
    Ok(())
}

/// Whether a server answers one query over `mode` on `port` (for
/// `bench`'s startup wait).
pub fn probe(mode: Mode, port: u16) -> bool {
    let Ok(q) = pack_query("example.org.", "A") else {
        return false;
    };
    let o = Opts {
        mode,
        server: IpAddr::from([127, 0, 0, 1]),
        port,
        queries: PathBuf::new(),
        clients: 1,
        threads: 1,
        outstanding: 1,
        secs: 0.0,
        rate: None,
        timeout: Duration::from_millis(500),
        ca: crate::root().join("bench/shared/tls/ca.pem"),
        tls: false,
        path: "/dns-query".into(),
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return false;
    };
    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), async {
            let (mut c, _keep) = connect(&o).await?;
            exchange(&mut c, &o, &Bytes::from(q)).await
        })
        .await
        .is_ok_and(|r| r.is_ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles() {
        let v: Vec<u32> = (1..=1000).collect();
        assert_eq!(pct(&v, 50.0), 500e-6);
        assert_eq!(pct(&v, 99.9), 999e-6);
        assert_eq!(pct(&v, 100.0), 1000e-6);
        assert_eq!(pct(&[], 50.0), 0.0);
    }

    #[test]
    fn packs_dnsperf_lines() {
        let q = pack_query("www.example.org", "aaaa").unwrap();
        let m = Message::from_vec(&q).unwrap();
        assert_eq!(m.metadata.id, 0);
        assert_eq!(m.queries[0].query_type(), RecordType::AAAA);
        assert_eq!(rcode_name(&q), "NOERROR");
    }
}
