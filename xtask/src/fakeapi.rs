//! A fake Kubernetes API server for scale benchmarks: serves N synthetic
//! Services (with one EndpointSlice of three endpoints each) spread over
//! namespaces, for list and watch. Watches send nothing after the initial
//! state; streaming-list watches (`sendInitialEvents=true`, used by
//! client-go >= 1.35) get ADDED events and the initial-events-end bookmark.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};

pub struct Objects {
    pub services: Vec<Value>,
    pub slices: Vec<Value>,
    pub namespaces: Vec<Value>,
}

pub fn generate(n: usize, namespaces: usize) -> Objects {
    generate_with(n, namespaces, false)
}

/// Like [`generate`]; with `external`, every Service also gets an
/// `externalIPs` entry (172.16.x.y) for `k8s_external`.
pub fn generate_with(n: usize, namespaces: usize, external: bool) -> Objects {
    let mut services = Vec::with_capacity(n);
    let mut slices = Vec::with_capacity(n);
    for i in 0..n {
        let ns = format!("ns-{}", i % namespaces);
        let name = format!("svc-{i}");
        let ip = format!("10.{}.{}.{}", 96 + (i >> 16), (i >> 8) & 255, i & 255);
        let mut svc = json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": ns, "uid": format!("s{i}"), "resourceVersion": "1"},
            "spec": {"type": "ClusterIP", "clusterIP": ip, "clusterIPs": [ip],
                     "ports": [{"name": "http", "port": 80, "protocol": "TCP"}, {"name": "metrics", "port": 9090, "protocol": "TCP"}]}
        });
        if external {
            svc["spec"]["externalIPs"] = json!([format!("172.16.{}.{}", (i >> 8) & 255, i & 255)]);
        }
        services.push(svc);
        let eps: Vec<Value> = (0..3)
            .map(|j| {
                let k = i * 3 + j;
                json!({"addresses": [format!("10.{}.{}.{}", 128 + (k >> 16), (k >> 8) & 255, k & 255)],
                       "conditions": {"ready": true},
                       "targetRef": {"kind": "Pod", "name": format!("{name}-{j}"), "namespace": ns}})
            })
            .collect();
        slices.push(json!({
            "apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSlice",
            "metadata": {"name": format!("{name}-abcde"), "namespace": ns, "uid": format!("e{i}"), "resourceVersion": "1",
                         "labels": {"kubernetes.io/service-name": name}},
            "addressType": "IPv4",
            "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}, {"name": "metrics", "port": 9090, "protocol": "TCP"}],
            "endpoints": eps
        }));
    }
    let namespaces = (0..namespaces)
        .map(|i| {
            json!({"apiVersion": "v1", "kind": "Namespace",
                        "metadata": {"name": format!("ns-{i}"), "uid": format!("n{i}"), "resourceVersion": "1"}})
        })
        .collect();
    Objects {
        services,
        slices,
        namespaces,
    }
}

type Body = BoxBody<Bytes, Infallible>;

fn full(status: u16, v: Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(v.to_string())).boxed())
        .unwrap()
}

/// A watch that sends `initial` events, then stays open until the client's timeout.
fn watch(initial: Vec<Value>, timeout: Duration) -> Response<Body> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(64);
    tokio::spawn(async move {
        for ev in initial {
            let mut line = ev.to_string();
            line.push('\n');
            if tx.send(Ok(Frame::data(Bytes::from(line)))).await.is_err() {
                return;
            }
        }
        tokio::time::sleep(timeout).await;
    });
    let stream = tokio_stream_from(rx);
    Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .header("Transfer-Encoding", "chunked")
        .body(StreamBody::new(stream).boxed())
        .unwrap()
}

fn tokio_stream_from(
    mut rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, Infallible>>,
) -> impl futures_util::Stream<Item = Result<Frame<Bytes>, Infallible>> {
    futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

fn list_kind(path: &str) -> Option<(&'static str, &'static str)> {
    match path {
        "/api/v1/services" => Some(("ServiceList", "v1")),
        "/apis/discovery.k8s.io/v1/endpointslices" => Some(("EndpointSliceList", "discovery.k8s.io/v1")),
        "/api/v1/namespaces" => Some(("NamespaceList", "v1")),
        "/api/v1/pods" => Some(("PodList", "v1")),
        _ => None,
    }
}

async fn handle(objs: Arc<Objects>, req: Request<hyper::body::Incoming>) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let param = |k: &str| {
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
            .map(|v| v.to_string())
    };
    let Some((kind, api_version)) = list_kind(&path) else {
        return Ok(full(
            404,
            json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 404, "reason": "NotFound"}),
        ));
    };
    let items: &[Value] = match path.as_str() {
        "/api/v1/services" => &objs.services,
        "/apis/discovery.k8s.io/v1/endpointslices" => &objs.slices,
        "/api/v1/namespaces" => &objs.namespaces,
        _ => &[],
    };
    let timeout = Duration::from_secs(param("timeoutSeconds").and_then(|t| t.parse().ok()).unwrap_or(300));
    if param("watch").is_some_and(|w| w == "true" || w == "1") {
        let mut initial = Vec::new();
        if param("sendInitialEvents").as_deref() == Some("true") {
            initial.extend(items.iter().map(|o| json!({"type": "ADDED", "object": o})));
            let item_kind = kind.trim_end_matches("List");
            initial.push(json!({"type": "BOOKMARK", "object": {
                "kind": item_kind, "apiVersion": api_version,
                "metadata": {"resourceVersion": "1", "annotations": {"k8s.io/initial-events-end": "true"}}}}));
        }
        return Ok(watch(initial, timeout));
    }
    // paginate like the API server: `limit` items, then a `continue` token
    let limit: usize = param("limit")
        .and_then(|l| l.parse().ok())
        .filter(|&l| l > 0)
        .unwrap_or(usize::MAX);
    let start: usize = param("continue").and_then(|c| c.parse().ok()).unwrap_or(0);
    let end = start.saturating_add(limit).min(items.len());
    let mut meta = json!({"resourceVersion": "1"});
    if end < items.len() {
        meta["continue"] = json!(end.to_string());
    }
    Ok(full(
        200,
        json!({"kind": kind, "apiVersion": api_version, "metadata": meta, "items": &items[start.min(end)..end]}),
    ))
}

/// Serve `objs` on 127.0.0.1 (random port) until the task is aborted.
pub async fn serve(objs: Objects) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let objs = Arc::new(objs);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let objs = objs.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| handle(objs.clone(), req));
                let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    Ok((addr, task))
}
