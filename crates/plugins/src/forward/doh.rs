//! DNS over HTTPS upstreams (RFC 8484), like CoreDNS's `lookupDoH` and
//! `pkg/doh`: HTTP/2 or HTTP/1.1 (by ALPN) with pooled connections,
//! `POST` (default) or `GET` to `/dns-query`.
//!
//! The request goes to the upstream's address; with `tls_servername` that
//! name is the TLS server name and the request's host, like CoreDNS's
//! `req.Host = dohHost`. Like CoreDNS, the answer is the response body,
//! whatever the HTTP status.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;

use super::proxy::ExchangeError;

/// `doh.MimeType`.
const MIME: &str = "application/dns-message";
/// Largest DNS message read from a body (`maxDNSQuerySize`).
const MAX_BODY: usize = 65536;

/// Resolves every name to the upstream's address: the URL's host may be
/// the TLS server name, but the connection goes to the configured IP.
#[derive(Clone)]
struct Fixed(SocketAddr);

impl tower_service::Service<Name> for Fixed {
    type Response = std::iter::Once<SocketAddr>;
    type Error = std::io::Error;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Name) -> Self::Future {
        std::future::ready(Ok(std::iter::once(self.0)))
    }
}

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector<Fixed>>, Full<Bytes>>;

/// The HTTP method of DoH queries (`doh_method`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

/// A DoH upstream's HTTP client.
pub struct DohClient {
    client: HttpsClient,
    /// `https://HOST[:PORT]/dns-query`
    url: String,
    method: Method,
    timeout: Duration,
}

/// Settings shared by the query and the health check clients.
pub struct DohSettings {
    pub addr: SocketAddr,
    pub tls: Arc<ClientConfig>,
    /// `tls_servername`: the TLS server name and the request's host.
    pub server_name: Option<String>,
    pub source: Option<IpAddr>,
    /// `max_idle_conns`, 0 is unlimited.
    pub max_idle_conns: usize,
}

impl DohClient {
    /// A client sending with `method`, each request (with its body) within
    /// `timeout` (`http.Client.Timeout`).
    pub fn new(s: &DohSettings, method: Method, timeout: Duration) -> Result<Self, String> {
        let mut http = HttpConnector::new_with_resolver(Fixed(s.addr));
        http.enforce_http(false);
        http.set_nodelay(true);
        http.set_local_address(s.source);
        // net.Dialer's timeout in http.DefaultTransport
        http.set_connect_timeout(Some(Duration::from_secs(30)));
        let mut tls = (*s.tls).clone();
        tls.alpn_protocols.clear();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_only()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http);
        let mut b = Client::builder(TokioExecutor::new());
        // http.DefaultTransport: idle connections are closed after 90s
        b.pool_idle_timeout(Duration::from_secs(90));
        if s.max_idle_conns > 0 {
            b.pool_max_idle_per_host(s.max_idle_conns);
        }
        let host = match &s.server_name {
            Some(n) => n.clone(),
            None => match s.addr.ip() {
                IpAddr::V4(ip) => ip.to_string(),
                IpAddr::V6(ip) => format!("[{ip}]"),
            },
        };
        let url = if s.addr.port() == 443 && s.server_name.is_some() {
            format!("https://{host}/dns-query")
        } else {
            format!("https://{host}:{}/dns-query", s.addr.port())
        };
        url.parse::<http::Uri>().map_err(|e| format!("DoH URL {url}: {e}"))?;
        Ok(Self {
            client: b.build(connector),
            url,
            method,
            timeout,
        })
    }

    /// Send `wire` (a packed query) and return the answer, and our address
    /// on the connection that carried it, if known.
    pub async fn exchange(&self, wire: Vec<u8>) -> Result<(Vec<u8>, Option<SocketAddr>), ExchangeError> {
        let req = match self.method {
            Method::Post => http::Request::post(&self.url).body(Full::new(Bytes::from(wire))),
            Method::Get => {
                let b64 = data_encoding::BASE64URL_NOPAD.encode(&wire);
                http::Request::get(format!("{}?dns={b64}", self.url)).body(Full::new(Bytes::new()))
            }
        };
        let mut req = req.map_err(|e| ExchangeError::InvalidRequest(e.to_string()))?;
        let h = req.headers_mut();
        h.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static(MIME));
        h.insert(http::header::ACCEPT, http::HeaderValue::from_static(MIME));
        let fut = async {
            let resp = self
                .client
                .request(req)
                .await
                .map_err(|e| ExchangeError::Http(e.to_string()))?;
            let local = resp
                .extensions()
                .get::<hyper_util::client::legacy::connect::HttpInfo>()
                .map(|i| i.local_addr());
            let body = Limited::new(resp.into_body(), MAX_BODY)
                .collect()
                .await
                .map_err(|e| ExchangeError::Http(e.to_string()))?
                .to_bytes();
            Ok((body.to_vec(), local))
        };
        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| ExchangeError::Timeout)?
    }
}
