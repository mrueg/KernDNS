//! The API client's request path: client-go's rate limiter
//! (`apiserver_qps`, `apiserver_burst`; 5 and 10 by default, like
//! client-go's), the `apiserver_max_inflight` limit and the
//! `coredns_kubernetes_rest_client_*` metrics, as a tower layer around
//! kube-rs's HTTP stack.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::{Request, Response};
use tokio::sync::Semaphore;
use tower::{Layer, Service, ServiceExt};

use crate::metrics::{RATE_LIMITER_LATENCY, REQUEST_LATENCY, REQUEST_RESULT};

/// client-go's `DefaultQPS` and `DefaultBurst`.
pub const DEFAULT_QPS: f32 = 5.0;
pub const DEFAULT_BURST: usize = 10;

/// `apiserver_qps`, `apiserver_burst` and `apiserver_max_inflight` (0:
/// the default, or no limit for the in-flight requests).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Limits {
    pub qps: f32,
    pub burst: usize,
    pub max_inflight: usize,
}

/// A token bucket like `flowcontrol.NewTokenBucketRateLimiter` (Go's
/// `rate.Limiter`): `burst` tokens, refilled at `qps` per second; a
/// request waits for its reserved token.
struct TokenBucket {
    qps: f64,
    burst: f64,
    state: Mutex<(f64, Instant)>,
}

impl TokenBucket {
    fn new(qps: f32, burst: usize) -> Self {
        Self {
            qps: qps as f64,
            burst: burst as f64,
            state: Mutex::new((burst as f64, Instant::now())),
        }
    }

    /// Reserve a token; how long to wait for it.
    fn reserve(&self) -> Duration {
        let mut st = self.state.lock().unwrap();
        let now = Instant::now();
        let (tokens, last) = *st;
        let tokens = (tokens + now.duration_since(last).as_secs_f64() * self.qps).min(self.burst) - 1.0;
        *st = (tokens, now);
        if tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-tokens / self.qps)
        }
    }
}

#[derive(Clone)]
pub struct ClientLayer {
    limiter: Arc<TokenBucket>,
    inflight: Option<Arc<Semaphore>>,
    /// The API server's `host:port`, the metrics' `host` label.
    host: Arc<str>,
}

impl ClientLayer {
    pub fn new(l: Limits, host: &str) -> Self {
        let qps = if l.qps > 0.0 { l.qps } else { DEFAULT_QPS };
        let burst = if l.burst > 0 { l.burst } else { DEFAULT_BURST };
        Self {
            limiter: Arc::new(TokenBucket::new(qps, burst)),
            inflight: (l.max_inflight > 0).then(|| Arc::new(Semaphore::new(l.max_inflight))),
            host: Arc::from(host),
        }
    }
}

impl<S> Layer<S> for ClientLayer {
    type Service = ClientService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ClientService {
            inner: Arc::new(tokio::sync::Mutex::new(inner)),
            layer: self.clone(),
        }
    }
}

/// The service [`ClientLayer`] builds. kube-rs's stack isn't `Clone`, so
/// the inner service is shared behind a lock that is only held to start a
/// request.
pub struct ClientService<S> {
    inner: Arc<tokio::sync::Mutex<S>>,
    layer: ClientLayer,
}

impl<S, B, RB> Service<Request<B>> for ClientService<S>
where
    S: Service<Request<B>, Response = Response<RB>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<RB>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<RB>, S::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // readiness is checked per request, under the lock
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let inner = self.inner.clone();
        let layer = self.layer.clone();
        Box::pin(async move {
            let verb = req.method().as_str().to_string();
            let host = layer.host.clone();
            // like client-go, a watch is neither rate limited nor timed
            // (only counted); everything else is both
            let watch = req
                .uri()
                .query()
                .is_some_and(|q| q.split('&').any(|kv| kv == "watch=true" || kv == "watch=1"));

            if !watch {
                let start = Instant::now();
                let wait = layer.limiter.reserve();
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
                RATE_LIMITER_LATENCY
                    .with_label_values(&[&verb, &*host])
                    .observe(start.elapsed().as_secs_f64());
            }

            // held until the response headers arrive, like client-go's
            // round tripper (a watch's body doesn't count)
            let _permit = match &layer.inflight {
                Some(s) => Some(s.clone().acquire_owned().await.expect("never closed")),
                None => None,
            };
            let start = Instant::now();
            let fut = {
                let mut svc = inner.lock().await;
                svc.ready().await?.call(req)
            };
            let res = fut.await;
            if !watch {
                REQUEST_LATENCY
                    .with_label_values(&[&verb, &*host])
                    .observe(start.elapsed().as_secs_f64());
            }
            let code = match &res {
                Ok(r) => r.status().as_u16().to_string(),
                Err(_) => "<error>".to_string(),
            };
            REQUEST_RESULT.with_label_values(&[&code, &verb, &*host]).inc();
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket() {
        let b = TokenBucket::new(5.0, 2);
        assert_eq!(b.reserve(), Duration::ZERO);
        assert_eq!(b.reserve(), Duration::ZERO);
        // the third waits for a token: 1/5 s
        let w = b.reserve();
        assert!(
            w > Duration::from_millis(150) && w <= Duration::from_millis(200),
            "{w:?}"
        );
        // and the fourth for the next one
        assert!(b.reserve() > Duration::from_millis(350));
    }

    #[tokio::test]
    async fn counts_requests_and_limits_inflight() {
        let svc = tower::service_fn(|_req: Request<()>| async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok::<_, std::convert::Infallible>(Response::builder().status(200).body(()).unwrap())
        });
        let layer = ClientLayer::new(
            Limits {
                qps: 1000.0,
                burst: 100,
                max_inflight: 1,
            },
            "kerndns-client-test:6443",
        );
        let mut s = layer.layer(svc);
        let host = "kerndns-client-test:6443";
        let before = REQUEST_RESULT.with_label_values(&["200", "GET", host]).get();
        let req = || Request::get("/api/v1/services").body(()).unwrap();
        let start = Instant::now();
        let (a, b) = tokio::join!(s.call(req()), s.call(req()));
        assert!(a.is_ok() && b.is_ok());
        // a watch is counted, not timed
        let w = Request::get("/api/v1/services?watch=true&resourceVersion=1")
            .body(())
            .unwrap();
        assert!(s.call(w).await.is_ok());
        // one at a time
        assert!(start.elapsed() >= Duration::from_millis(40));
        assert_eq!(
            REQUEST_RESULT.with_label_values(&["200", "GET", host]).get(),
            before + 3.0
        );
        assert_eq!(REQUEST_LATENCY.with_label_values(&["GET", host]).get_sample_count(), 2);
    }
}
