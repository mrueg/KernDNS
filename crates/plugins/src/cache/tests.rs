//! Ports of CoreDNS's `plugin/cache` unit tests (`cache_test.go`,
//! `prefetch_test.go`, `serve_stale_recheck_test.go`, `setup_test.go`).
//! The Go tests replace `Cache.now`; these move [`Clock`] instead.

use super::*;
use crate::testutil::*;
use kerndns_core::CaptureWriter;
use kerndns_core::proto::op::Edns;
use kerndns_core::proto::rr::rdata::{A, CNAME};
use std::sync::atomic::AtomicU32;
use tokio::sync::{Semaphore, mpsc};

const MIN: Duration = Duration::from_secs(60);
/// What a Go test handler returning 255 means: the upstream was asked.
const ASKED: ResponseCode = ResponseCode::Unknown(255);

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

/// A record in presentation format.
fn rr(s: &str) -> Record {
    crate::file::zonefile::new_rr(s).unwrap().unwrap()
}

fn soa(ttl: u32) -> Record {
    rr(&format!(
        "example.org. {ttl} IN SOA sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600"
    ))
}

fn q(name: &str) -> Request {
    query(name, RecordType::A, "10.240.0.1:40212")
}

/// `req.SetEdns0(4096, true)`.
fn with_do(mut req: Request) -> Request {
    let mut e = Edns::new();
    e.set_max_payload(4096);
    e.set_dnssec_ok(true);
    req.msg.edns = Some(e);
    req
}

fn a_of(m: &Message) -> (String, u32) {
    let r = &m.answers[0];
    match &r.data {
        RData::A(a) => (a.0.to_string(), r.ttl),
        d => panic!("not an A record: {d:?}"),
    }
}

/// A next handler made of a closure: the message to write and the result.
struct Func<F>(F);

#[async_trait]
impl<F> Handler for Func<F>
where
    F: Fn(&Request) -> (Option<Message>, HandlerResult) + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "func"
    }
    async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let (m, res) = (self.0)(req);
        if let Some(m) = m {
            let _ = w.write_msg(m).await;
        }
        res
    }
}

fn func<F>(f: F) -> Arc<dyn Handler>
where
    F: Fn(&Request) -> (Option<Message>, HandlerResult) + Send + Sync + 'static,
{
    Arc::new(Func(f))
}

/// `ttlBackend`.
fn ttl_backend(ttl: u32) -> Arc<dyn Handler> {
    func(move |r| {
        let mut m = r.reply();
        m.metadata.recursion_available = true;
        m.answers = vec![rr(&format!("{} {ttl} IN A 127.0.0.53", r.qname()))];
        (Some(m), Ok(ResponseCode::NoError))
    })
}

/// `nxDomainBackend`.
fn nx_backend(ttl: u32) -> Arc<dyn Handler> {
    func(move |r| {
        let mut m = r.error_reply(ResponseCode::NXDomain);
        m.metadata.recursion_available = true;
        m.authorities = vec![soa(ttl)];
        (Some(m), Ok(ResponseCode::NXDomain))
    })
}

/// `servFailBackend`.
fn servfail_backend(ttl: u32) -> Arc<dyn Handler> {
    func(move |r| {
        let mut m = r.error_reply(ResponseCode::ServFail);
        m.metadata.recursion_available = true;
        m.authorities = vec![soa(ttl)];
        (Some(m), Ok(ResponseCode::ServFail))
    })
}

/// A backend that writes nothing and returns 255.
fn asked_backend() -> Arc<dyn Handler> {
    func(|_| (None, Ok(ASKED)))
}

/// The next handler, swapped by the tests like Go's `c.Next = ...`.
#[derive(Clone)]
struct Switch(Arc<Mutex<Arc<dyn Handler>>>);

impl Switch {
    fn set(&self, h: Arc<dyn Handler>) {
        *self.0.lock().unwrap() = h;
    }
}

#[async_trait]
impl Handler for Switch {
    fn name(&self) -> &'static str {
        "switch"
    }
    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let h = self.0.lock().unwrap().clone();
        h.serve_dns(ctx, w, req).await
    }
}

/// Calls `inner` after counting the call, reporting the start and waiting
/// for a release; reports completion (Go's started/release/completed
/// channels).
struct Gated {
    calls: Arc<AtomicU32>,
    started: mpsc::UnboundedSender<()>,
    release: Arc<Semaphore>,
    completed: mpsc::UnboundedSender<()>,
    inner: Arc<dyn Handler>,
}

#[async_trait]
impl Handler for Gated {
    fn name(&self) -> &'static str {
        "gated"
    }
    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _ = self.started.send(());
        if let Ok(p) = self.release.acquire().await {
            p.forget();
        }
        let res = self.inner.serve_dns(ctx, w, req).await;
        let _ = self.completed.send(());
        res
    }
}

struct Gate {
    calls: Arc<AtomicU32>,
    started: mpsc::UnboundedReceiver<()>,
    release: Arc<Semaphore>,
    completed: mpsc::UnboundedReceiver<()>,
}

fn gated(inner: Arc<dyn Handler>) -> (Arc<dyn Handler>, Gate) {
    let (st, sr) = mpsc::unbounded_channel();
    let (ct, cr) = mpsc::unbounded_channel();
    let calls = Arc::new(AtomicU32::new(0));
    let release = Arc::new(Semaphore::new(0));
    let h = Gated {
        calls: calls.clone(),
        started: st,
        release: release.clone(),
        completed: ct,
        inner,
    };
    (
        Arc::new(h),
        Gate {
            calls,
            started: sr,
            release,
            completed: cr,
        },
    )
}

impl Gate {
    fn calls(&self) -> u32 {
        self.calls.load(Ordering::SeqCst)
    }
}

async fn signal(rx: &mut mpsc::UnboundedReceiver<()>, failure: &str) {
    tokio::time::timeout(secs(2), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{failure}"));
}

/// `waitForStaleRefresh`.
async fn wait_refresh(completed: &mut mpsc::UnboundedReceiver<()>, item: &Item) {
    signal(completed, "background refresh did not complete").await;
    let deadline = Instant::now() + secs(2);
    while item.refreshing.load(Ordering::Acquire) {
        assert!(
            Instant::now() < deadline,
            "background refresh did not release the cache item"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// A cache with Go's `New()` defaults changed by `f`, and its next handler.
fn new_cache(f: impl FnOnce(&mut CacheCore)) -> (Arc<Cache>, Switch) {
    let mut core = CacheCore::new(DEFAULT_CAP, DEFAULT_CAP);
    f(&mut core);
    from_core(core)
}

fn from_core(core: CacheCore) -> (Arc<Cache>, Switch) {
    let sw = Switch(Arc::new(Mutex::new(asked_backend())));
    let next: Arc<dyn Handler> = Arc::new(sw.clone());
    (
        Arc::new(Cache {
            core: Arc::new(core),
            bypass: Default::default(),
            next: Some(next),
        }),
        sw,
    )
}

/// `cacheParse` of `cache {\n<cfg>\n}`.
fn parse_cfg(cfg: &str) -> Result<CacheCore, String> {
    with_controller("cache", &format!("cache {{\n{cfg}\n}}"), parse).map_err(|e| e.to_string())
}

/// Serve `req` and return the result and the message written.
async fn ask(c: &Cache, req: &Request) -> (HandlerResult, Option<Message>) {
    let (res, w) = serve(c, req).await;
    (res, w.msg().cloned())
}

fn rcode(res: &HandlerResult) -> ResponseCode {
    result_rcode(res)
}

// --- setup_test.go ---

#[test]
fn setup() {
    assert!(setup_ok(&Setup, "cache"));
    assert!(setup_ok(
        &Setup,
        "cache 300 example.org {\n success 5000 600 10\n denial 1000\n prefetch 10 1m 20%\n serve_stale 1h verify\n servfail 10s\n disable denial sub.example.org\n keepttl\n}"
    ));
    assert!(setup_err(&Setup, "cache 0").contains("can not be zero or negative"));
    assert!(setup_err(&Setup, "cache {\n prefetch 1 1m 5%\n}").contains("range [10, 90]"));
    assert!(setup_err(&Setup, "cache {\n servfail 10m\n}").contains("over 5 minutes"));
    assert!(setup_err(&Setup, "cache {\n disable foo\n}").contains("must be \"success\" or \"denial\""));
    assert!(
        setup_err(&Setup, "cache {\n serve_stale_policy prefer_positive\n}")
            .contains("serve_stale_policy requires serve_stale")
    );
}

/// TestServeStale: staleUpTo, verifyStale, verifyStaleTimeout, staleTTL.
#[test]
fn serve_stale_setup() {
    let ms = Duration::from_millis;
    let ok: &[(&str, Duration, bool, Duration, u32)] = &[
        ("serve_stale", secs(3600), false, Duration::ZERO, 0),
        ("serve_stale 20m", 20 * MIN, false, Duration::ZERO, 0),
        ("serve_stale 1h20m", 80 * MIN, false, Duration::ZERO, 0),
        ("serve_stale 0m", Duration::ZERO, false, Duration::ZERO, 0),
        ("serve_stale 0", Duration::ZERO, false, Duration::ZERO, 0),
        ("serve_stale 0 verify", Duration::ZERO, true, Duration::ZERO, 0),
        ("serve_stale 0 immediate", Duration::ZERO, false, Duration::ZERO, 0),
        ("serve_stale 0 VERIFY", Duration::ZERO, true, Duration::ZERO, 0),
        ("serve_stale 1h immediate 30s", secs(3600), false, Duration::ZERO, 30),
        (
            "serve_stale 1h immediate 30s 30s",
            secs(3600),
            false,
            Duration::ZERO,
            30,
        ),
        (
            "serve_stale 1h immediate 4294967295s",
            secs(3600),
            false,
            Duration::ZERO,
            u32::MAX,
        ),
        ("serve_stale 1h immediate 0", secs(3600), false, Duration::ZERO, 0),
        ("serve_stale 1h verify 100ms", secs(3600), true, ms(100), 0),
        ("serve_stale 1h verify 100ms 30s", secs(3600), true, ms(100), 30),
        ("serve_stale 1h verify 100ms 30s 30s", secs(3600), true, ms(100), 30),
        ("serve_stale 1h verify 0", secs(3600), true, Duration::ZERO, 0),
        ("serve_stale 1h verify 0 1m", secs(3600), true, Duration::ZERO, 60),
        ("serve_stale 1h VERIFY 250ms", secs(3600), true, ms(250), 0),
    ];
    for (i, (input, up_to, verify, timeout, ttl)) in ok.iter().enumerate() {
        let c = parse_cfg(input).unwrap_or_else(|e| panic!("Test {i}: {input}: {e}"));
        assert_eq!(
            (c.stale_up_to, c.verify_stale, c.verify_stale_timeout, c.stale_ttl),
            (*up_to, *verify, *timeout, *ttl),
            "Test {i}: {input}"
        );
    }
    for input in [
        "serve_stale 20",
        "serve_stale -20m",
        "serve_stale aa",
        "serve_stale 1m nono",
        "serve_stale 0 after nono",
        "serve_stale 1h immediate 100ms",
        "serve_stale 1h immediate 4294967296s",
        "serve_stale 1h immediate -1s",
        "serve_stale 1h immediate garbage",
        "serve_stale 1h immediate 30s extra",
        "serve_stale 1h verify -1ms",
        "serve_stale 1h verify garbage",
        "serve_stale 1h verify 100ms 500ms",
        "serve_stale 1h verify 100ms -1s",
        "serve_stale 1h verify 100ms garbage",
        "serve_stale 1h verify 100ms 30s extra",
    ] {
        assert!(parse_cfg(input).is_err(), "{input} should fail");
    }
    // Go's error messages
    for (input, want) in [
        (
            "serve_stale 1m nono",
            "invalid value for serve_stale refresh mode: nono",
        ),
        ("serve_stale -20m", "invalid negative duration for serve_stale"),
        (
            "serve_stale 1h immediate 100ms",
            "serve_stale response TTL must be a whole number of seconds",
        ),
        (
            "serve_stale 1h immediate 4294967296s",
            "serve_stale response TTL exceeds the DNS TTL range",
        ),
        (
            "serve_stale 1h immediate -1s",
            "invalid negative response TTL for serve_stale",
        ),
        (
            "serve_stale 1h immediate garbage",
            "invalid serve_stale response TTL: time: invalid duration",
        ),
        (
            "serve_stale 1h verify -1ms",
            "invalid negative timeout for serve_stale verify",
        ),
        (
            "serve_stale 1h verify garbage",
            "invalid serve_stale verify timeout: time: invalid duration",
        ),
        (
            "serve_stale 1h immediate 30s extra",
            "invalid serve_stale failure recheck",
        ),
        ("serve_stale 1h verify 100ms 30s 30s extra", "Wrong argument count"),
    ] {
        let e = parse_cfg(input).err().unwrap();
        assert!(e.contains(want), "{input}: {e}");
    }
}

/// TestServeStaleFailureRecheck.
#[test]
fn serve_stale_failure_recheck_setup() {
    for (input, want) in [
        ("serve_stale 1h immediate 30s 30s", secs(30)),
        ("serve_stale 1h immediate 0 0", Duration::ZERO),
        ("serve_stale 1h verify 100ms 30s 250ms", Duration::from_millis(250)),
        ("serve_stale 1h verify 0 0 5m", 5 * MIN),
    ] {
        assert_eq!(parse_cfg(input).unwrap().stale_recheck, want, "{input}");
    }
    for (input, want) in [
        (
            "serve_stale 1h immediate 30s -1s",
            "invalid negative failure recheck for serve_stale",
        ),
        (
            "serve_stale 1h immediate 30s 5m1s",
            "serve_stale failure recheck cannot exceed 5 minutes",
        ),
        (
            "serve_stale 1h immediate 30s invalid",
            "invalid serve_stale failure recheck",
        ),
        ("serve_stale 1h immediate 30s 30s extra", "Wrong argument count"),
        (
            "serve_stale 1h verify 100ms 30s -1s",
            "invalid negative failure recheck",
        ),
        ("serve_stale 1h verify 100ms 30s 30s extra", "Wrong argument count"),
    ] {
        let e = parse_cfg(input).err().unwrap();
        assert!(e.contains(want), "{input}: {e}");
    }
}

/// TestServeStalePolicy.
#[test]
fn serve_stale_policy_setup() {
    for (input, pp) in [
        ("serve_stale\nserve_stale_policy prefer_positive", true),
        ("serve_stale_policy PREFER_POSITIVE\nserve_stale", true),
        ("serve_stale", false),
    ] {
        assert_eq!(parse_cfg(input).unwrap().prefer_positive, pp, "{input}");
    }
    for (input, want) in [
        (
            "serve_stale_policy prefer_positive",
            "serve_stale_policy requires serve_stale",
        ),
        ("serve_stale\nserve_stale_policy", "Wrong argument count"),
        (
            "serve_stale\nserve_stale_policy prefer_positive extra",
            "Wrong argument count",
        ),
        (
            "serve_stale\nserve_stale_policy invalid",
            "invalid serve_stale_policy: invalid",
        ),
        (
            "serve_stale\nserve_stale_policy prefer_positive\nserve_stale_policy prefer_positive",
            "serve_stale_policy can only be specified once",
        ),
    ] {
        let e = parse_cfg(input).err().unwrap();
        assert!(e.contains(want), "{input}: {e}");
    }
}

// --- KernDNS's own ---

#[tokio::test]
async fn caches_positive_answers_with_min_ttl() {
    let calls = Arc::new(AtomicU32::new(0));
    let (c, sw) = new_cache(|_| {});
    let n = calls.clone();
    sw.set(func(move |r| {
        n.fetch_add(1, Ordering::Relaxed);
        let mut m = r.reply();
        m.answers.push(Record::from_rdata(
            r.qname().clone(),
            300,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        m.answers.push(Record::from_rdata(
            r.qname().clone(),
            30,
            RData::A(A::new(192, 0, 2, 2)),
        ));
        (Some(m), Ok(ResponseCode::NoError))
    }));
    let req = q("a.example.org.");
    let (_, first) = ask(&c, &req).await;
    // every record gets the minimal TTL of the response
    assert!(first.unwrap().answers.iter().all(|r| r.ttl == 30));
    let (_, m) = ask(&c, &req).await;
    assert_eq!(m.unwrap().answers.len(), 2);
    assert_eq!(calls.load(Ordering::Relaxed), 1, "second query served from cache");
    // different type: miss
    let _ = ask(&c, &query("a.example.org.", RecordType::AAAA, "10.0.0.1:1")).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn caches_nxdomain_with_soa() {
    let (c, sw) = new_cache(|_| {});
    sw.set(nx_backend(120));
    let req = q("nx.example.org.");
    let _ = ask(&c, &req).await;
    sw.set(asked_backend());
    let (_, m) = ask(&c, &req).await;
    let m = m.unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(m.authorities[0].ttl, 120);
}

#[test]
fn nodata_detection() {
    let req = q("a.example.org.");
    let mut m = req.reply();
    m.answers.push(Record::from_rdata(
        req.qname().clone(),
        60,
        RData::CNAME(CNAME(Name::from_ascii("b.example.org.").unwrap())),
    ));
    assert!(is_nodata(&m), "dangling CNAME doesn't answer the question");
    m.answers.push(rr("b.example.org. 60 IN A 1.2.3.4"));
    assert!(!is_nodata(&m));
}

// --- cache_test.go ---

/// TestCacheZeroTTL.
#[tokio::test]
async fn zero_ttl() {
    let (c, sw) = new_cache(|c| {
        c.minpttl = Duration::ZERO;
        c.minnttl = Duration::ZERO;
    });
    sw.set(ttl_backend(0));
    let _ = ask(&c, &q("example.org.")).await;
    assert_eq!(c.core.pcache.len(), 0, "Msg with 0 TTL should not have been cached");
    assert_eq!(c.core.ncache.len(), 0, "Msg with 0 TTL should not have been cached");
}

/// TestCacheHonorsConfiguredPositiveMaxTTLAboveDefault.
#[tokio::test]
async fn positive_max_ttl_above_default() {
    let (c, sw) = new_cache(|c| {
        c.pttl = secs(7200);
        c.minpttl = Duration::ZERO;
    });
    sw.set(ttl_backend(86400));
    let (_, m) = ask(&c, &q("example.org.")).await;
    assert_eq!(m.unwrap().answers[0].ttl, 7200);
}

/// TestCacheServfailTTL0.
#[tokio::test]
async fn servfail_ttl0() {
    let (c, sw) = new_cache(|c| c.failttl = Duration::ZERO);
    sw.set(servfail_backend(0));
    let _ = ask(&c, &q("example.org.")).await;
    assert_eq!(c.core.ncache.len(), 0, "SERVFAIL response should not have been cached");
}

fn timeout_backend(calls: Arc<AtomicU32>) -> Arc<dyn Handler> {
    func(move |_| {
        calls.fetch_add(1, Ordering::SeqCst);
        (None, Err(PluginError::servfail("test", "upstream timeout")))
    })
}

/// TestCacheServfailOnTimeout.
#[tokio::test]
async fn servfail_on_timeout() {
    let calls = Arc::new(AtomicU32::new(0));
    let (c, sw) = new_cache(|c| c.failttl = secs(5));
    sw.set(timeout_backend(calls.clone()));
    let req = q("example.org.");
    let (res, _) = ask(&c, &req).await;
    assert!(res.is_err() && rcode(&res) == ResponseCode::ServFail);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let (res, m) = ask(&c, &req).await;
    assert_eq!(res.unwrap(), ResponseCode::NoError, "expected cached response");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the timeout should be cached");
    assert_eq!(m.unwrap().metadata.response_code, ResponseCode::ServFail);
}

/// TestCacheServfailOnTimeoutDisabled.
#[tokio::test]
async fn servfail_on_timeout_disabled() {
    let calls = Arc::new(AtomicU32::new(0));
    let (c, sw) = new_cache(|c| c.failttl = Duration::ZERO);
    sw.set(timeout_backend(calls.clone()));
    let req = q("example.org.");
    let _ = ask(&c, &req).await;
    let _ = ask(&c, &req).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// TestServeFromStaleCache.
#[tokio::test]
async fn serve_from_stale_cache() {
    let (c, sw) = new_cache(|c| c.stale_up_to = secs(3600));
    sw.set(ttl_backend(60));
    let _ = ask(&c, &q("cached.org.")).await;
    assert_eq!(c.core.pcache.len(), 1, "Msg with > 0 TTL should have been cached");
    sw.set(asked_backend());
    for (i, (name, minutes, want)) in [
        ("cached.org.", 30, ResponseCode::NoError),
        ("cached.org.", 60, ResponseCode::NoError),
        ("cached.org.", 70, ASKED),
        ("notcached.org.", 30, ASKED),
        ("notcached.org.", 60, ASKED),
        ("notcached.org.", 70, ASKED),
    ]
    .into_iter()
    .enumerate()
    {
        c.core.clock.set(minutes * MIN);
        let (res, _) = ask(&c, &q(name)).await;
        assert_eq!(rcode(&res), want, "Test {i}");
    }
}

/// TestServeFromStaleCacheResponseTTL.
#[tokio::test]
async fn serve_from_stale_cache_response_ttl() {
    for (name, cfg, prime, advance, want) in [
        (
            "legacy default",
            "serve_stale 1h immediate",
            ResponseCode::NoError,
            2 * MIN,
            0,
        ),
        (
            "immediate positive",
            "serve_stale 1h immediate 30s",
            ResponseCode::NoError,
            2 * MIN,
            30,
        ),
        (
            "exact expiry",
            "serve_stale 1h immediate 30s",
            ResponseCode::NoError,
            MIN,
            30,
        ),
        (
            "immediate negative",
            "serve_stale 1h immediate 25s",
            ResponseCode::NXDomain,
            2 * MIN,
            25,
        ),
        (
            "verify failure",
            "serve_stale 1h verify 0 45s",
            ResponseCode::NoError,
            2 * MIN,
            45,
        ),
        (
            "stale ttl overrides keepttl",
            "serve_stale 1h immediate 17s\nkeepttl",
            ResponseCode::NoError,
            2 * MIN,
            17,
        ),
        (
            "fresh response is unchanged",
            "serve_stale 1h immediate 30s",
            ResponseCode::NoError,
            secs(10),
            50,
        ),
    ] {
        let (c, sw) = from_core(parse_cfg(cfg).unwrap());
        sw.set(if prime == ResponseCode::NoError {
            ttl_backend(60)
        } else {
            nx_backend(60)
        });
        let req = q("cached.org.");
        let (res, _) = ask(&c, &req).await;
        assert_eq!(rcode(&res), prime, "{name}: priming");
        c.core.clock.set(advance);
        sw.set(servfail_backend(60));
        let (res, m) = ask(&c, &req).await;
        assert_eq!(res.unwrap(), ResponseCode::NoError, "{name}");
        let m = m.unwrap();
        assert_eq!(m.metadata.response_code, prime, "{name}");
        let got = if prime == ResponseCode::NXDomain {
            m.authorities[0].ttl
        } else {
            m.answers[0].ttl
        };
        assert_eq!(got, want, "{name}");
    }
}

/// TestServeFromStaleCacheFetchVerify.
#[tokio::test]
async fn serve_from_stale_cache_fetch_verify() {
    let (c, sw) = new_cache(|c| {
        c.stale_up_to = secs(3600);
        c.verify_stale = true;
    });
    sw.set(ttl_backend(120));
    let _ = ask(&c, &q("cached.org.")).await;
    assert_eq!(c.core.pcache.len(), 1);
    for (i, (up_rcode, up_ttl, minutes, want_rcode, want_ttl)) in [
        // after 1 minute: the cached response, not refreshed
        (ResponseCode::NoError, 200, 1, ResponseCode::NoError, 60),
        // after 2 more: the upstream's, because it's available
        (ResponseCode::NoError, 200, 3, ResponseCode::NoError, 200),
        // expired and the upstream fails: the cached entry
        (ResponseCode::ServFail, 200, 7, ResponseCode::NoError, 0),
        // NXDOMAIN from upstream wins, despite the serve stale period
        (ResponseCode::NXDomain, 150, 8, ResponseCode::NXDomain, 150),
    ]
    .into_iter()
    .enumerate()
    {
        c.core.clock.set(minutes * MIN);
        sw.set(match up_rcode {
            ResponseCode::NoError => ttl_backend(up_ttl),
            ResponseCode::ServFail => servfail_backend(up_ttl),
            _ => nx_backend(up_ttl),
        });
        let (res, m) = ask(&c, &q("cached.org.")).await;
        assert_eq!(rcode(&res), want_rcode, "Test {i}");
        let m = m.unwrap();
        let ttl = if want_rcode == ResponseCode::NoError {
            m.answers[0].ttl
        } else {
            m.authorities[0].ttl
        };
        assert_eq!(ttl, want_ttl, "Test {i}");
    }
}

/// `slowTTLBackend`.
fn slow_ttl_backend(ttl: u32, delay: Duration, done: mpsc::UnboundedSender<()>) -> Arc<dyn Handler> {
    struct Slow(Arc<dyn Handler>, Duration, mpsc::UnboundedSender<()>);
    #[async_trait]
    impl Handler for Slow {
        fn name(&self) -> &'static str {
            "slow"
        }
        async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
            tokio::time::sleep(self.1).await;
            let res = self.0.serve_dns(ctx, w, req).await;
            let _ = self.2.send(());
            res
        }
    }
    Arc::new(Slow(ttl_backend(ttl), delay, done))
}

/// TestServeFromStaleCacheFetchVerifyTimeout.
#[tokio::test]
async fn fetch_verify_timeout() {
    let (c, sw) = new_cache(|c| {
        c.stale_up_to = secs(3600);
        c.verify_stale = true;
        c.verify_stale_timeout = Duration::from_millis(50);
        c.stale_ttl = 30;
    });
    sw.set(ttl_backend(120));
    let req = q("cached.org.");
    let _ = ask(&c, &req).await;
    assert_eq!(c.core.pcache.len(), 1);
    c.core.clock.set(3 * MIN);
    let (tx, mut done) = mpsc::unbounded_channel();
    sw.set(slow_ttl_backend(60, Duration::from_millis(200), tx));
    let start = Instant::now();
    let (res, m) = ask(&c, &req).await;
    let elapsed = start.elapsed();
    assert_eq!(res.unwrap(), ResponseCode::NoError);
    assert!(elapsed < Duration::from_millis(150), "took {elapsed:?}");
    assert_eq!(m.unwrap().answers[0].ttl, 30, "stale TTL");
    signal(&mut done, "background verify never completed").await;
    // the background verify refreshed the cache
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (_, m) = ask(&c, &req).await;
    assert_eq!(m.unwrap().answers[0].ttl, 60);
}

/// TestServeFromStaleCacheFetchVerifyTimeoutFastUpstream.
#[tokio::test]
async fn fetch_verify_timeout_fast_upstream() {
    let (c, sw) = new_cache(|c| {
        c.stale_up_to = secs(3600);
        c.verify_stale = true;
        c.verify_stale_timeout = Duration::from_millis(500);
    });
    sw.set(ttl_backend(120));
    let req = q("cached.org.");
    let _ = ask(&c, &req).await;
    c.core.clock.set(3 * MIN);
    sw.set(ttl_backend(200));
    let (res, m) = ask(&c, &req).await;
    assert_eq!(res.unwrap(), ResponseCode::NoError);
    let m = m.unwrap();
    assert_eq!(m.answers[0].ttl, 200, "fresh TTL");
    assert!(!m.metadata.authoritative);
}

/// TestServeFromStaleCacheFetchVerifyTimeoutUncacheableResponse.
#[tokio::test]
async fn fetch_verify_timeout_uncacheable_response() {
    let (c, sw) = new_cache(|c| {
        c.stale_up_to = secs(3600);
        c.verify_stale = true;
        c.verify_stale_timeout = secs(1);
    });
    sw.set(ttl_backend(60));
    let req = q("cached.org.");
    let _ = ask(&c, &req).await;
    c.core.clock.set(2 * MIN);
    // NXDOMAIN without SOA: not cacheable, but a refresh
    sw.set(func(|r| {
        (Some(r.error_reply(ResponseCode::NXDomain)), Ok(ResponseCode::NXDomain))
    }));
    let (res, m) = ask(&c, &req).await;
    assert_eq!(res.unwrap(), ResponseCode::NoError);
    let m = m.unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    for r in m.answers.iter().chain(&m.authorities).chain(&m.additionals) {
        assert!(r.ttl <= MAXIMUM_DEFAULT_TTL.as_secs() as u32);
    }
}

/// TestServeFromStaleCacheFetchVerifyTimeoutMetadataIsolation: the
/// background verify sees the request's metadata, and what it sets stays
/// out of the request's.
#[tokio::test]
async fn fetch_verify_timeout_metadata_isolation() {
    let (c, sw) = new_cache(|c| {
        c.stale_up_to = secs(3600);
        c.verify_stale = true;
        c.verify_stale_timeout = Duration::from_millis(20);
    });
    sw.set(ttl_backend(120));
    let req = q("cached.org.");
    let _ = ask(&c, &req).await;
    c.core.clock.set(3 * MIN);

    struct Meta(mpsc::UnboundedSender<String>, Arc<Semaphore>);
    #[async_trait]
    impl Handler for Meta {
        fn name(&self) -> &'static str {
            "meta"
        }
        async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
            let _ = self
                .0
                .send(ctx.metadata.get("test/request").cloned().unwrap_or_default());
            let _ = self.1.acquire().await.map(|p| p.forget());
            ctx.metadata.insert("test/background".into(), "set".into());
            let mut m = req.reply();
            m.answers = vec![rr("cached.org. 60 IN A 127.0.0.54")];
            let _ = w.write_msg(m).await;
            let _ = self.0.send("done".into());
            Ok(ResponseCode::NoError)
        }
    }
    let (tx, mut rx) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    sw.set(Arc::new(Meta(tx, release.clone())));
    let mut ctx = Context::new(".", "dns://:53");
    ctx.metadata.insert("test/request".into(), "preserved".into());
    let mut w = CaptureWriter::new();
    let res = c.serve_dns(&mut ctx, &mut w, &req).await;
    assert_eq!(res.unwrap(), ResponseCode::NoError);
    let got = tokio::time::timeout(secs(1), rx.recv()).await.unwrap().unwrap();
    assert_eq!(got, "preserved");
    release.add_permits(1);
    let done = tokio::time::timeout(secs(1), rx.recv()).await.unwrap().unwrap();
    assert_eq!(done, "done");
    assert!(!ctx.metadata.contains_key("test/background"));
}

/// TestNegativeStaleMaskingPositiveCache.
#[tokio::test]
async fn negative_stale_masking_positive_cache() {
    let (c, sw) = new_cache(|c| c.stale_up_to = 10 * MIN);
    sw.set(nx_backend(60));
    let req = q("cached.org.");
    let (res, _) = ask(&c, &req).await;
    assert_eq!(rcode(&res), ResponseCode::NXDomain);
    assert_ne!(c.core.ncache.len(), 0);
    assert_eq!(c.core.pcache.len(), 0);

    sw.set(asked_backend());
    let (_, m) = ask(&c, &req).await;
    assert_eq!(m.unwrap().metadata.response_code, ResponseCode::NXDomain);

    // stale, not yet beyond serve_stale: NXDOMAIN, and a refresh that
    // brings a positive answer
    c.core.clock.set(5 * MIN);
    sw.set(func(|r| {
        let mut m = r.reply();
        m.metadata.recursion_available = true;
        m.answers = vec![rr(&format!("{} 303 IN A 127.0.0.53", r.qname()))];
        (Some(m), Ok(ResponseCode::NoError))
    }));
    let (_, m) = ask(&c, &req).await;
    assert_eq!(m.unwrap().metadata.response_code, ResponseCode::NXDomain);
    for _ in 0..300 {
        if c.core.ncache.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(c.core.ncache.len(), 0, "the refresh removes the negative entry");
    assert_eq!(c.core.pcache.len(), 1);

    sw.set(asked_backend());
    let (res, _) = ask(&c, &req).await;
    assert_eq!(rcode(&res), ResponseCode::NoError);
}

/// TestCacheKeepTTL.
#[tokio::test]
async fn keep_ttl() {
    let (c, sw) = new_cache(|c| c.keepttl = true);
    sw.set(ttl_backend(60));
    let _ = ask(&c, &q("cached.org.")).await;
    for (i, (name, s)) in [("cached.org.", 0), ("cached.org.", 30), ("uncached.org.", 60)]
        .into_iter()
        .enumerate()
    {
        c.core.clock.set(secs(s));
        let (_, m) = ask(&c, &q(name)).await;
        assert_eq!(m.unwrap().answers[0].ttl, 60, "Test {i}");
    }
}

/// TestCacheSeparation: the key separates qtype, DO and CD, not AA.
#[test]
fn separation() {
    let make = |qtype: RecordType, do_bit: bool, cd: bool, aa: bool| {
        let mut r = query("example.org.", qtype, "10.240.0.1:1");
        if do_bit {
            r = with_do(r);
        }
        r.msg.metadata.checking_disabled = cd;
        r.msg.metadata.authoritative = aa;
        r
    };
    for (name, query, cached) in [
        ("query type", make(RecordType::AAAA, false, false, false), false),
        ("DO bit", make(RecordType::A, true, false, false), false),
        ("CD bit", make(RecordType::A, false, true, false), false),
        ("CD and DO bit", make(RecordType::A, true, true, false), false),
        ("CD, DO and query type", make(RecordType::MX, true, true, false), false),
        (
            "AA bit is not part of the key",
            make(RecordType::A, false, false, true),
            true,
        ),
    ] {
        let core = CacheCore::new(DEFAULT_CAP, DEFAULT_CAP);
        let initial = make(RecordType::A, false, false, false);
        let m = initial.reply();
        let t = cache_response_type(&m, SystemTime::now());
        let w = CacheWriter::new(&core, &initial, "dns://:53", "");
        if let Some(k) = cache_key(&initial.name(), &m, t, false, false) {
            core.set(&w, &m, k, t, core.pttl);
        }
        let found = core.get(Instant::now(), &query, "dns://:53", "").is_some();
        assert_eq!(found, cached, "{name}");
    }
}

fn positive(req: &Request, a: &str) -> Message {
    let mut m = req.reply();
    m.answers = vec![rr(a)];
    m
}

fn negative(req: &Request) -> Message {
    let mut m = req.error_reply(ResponseCode::NXDomain);
    m.authorities = vec![rr(
        "example.org. 300 IN SOA ns.example.org. hostmaster.example.org. 1 7200 3600 1209600 300",
    )];
    m
}

/// TestServfailDoesNotShadowPositiveCache.
#[test]
fn servfail_does_not_shadow_positive_cache() {
    let mut core = CacheCore::new(DEFAULT_CAP, DEFAULT_CAP);
    core.stale_up_to = secs(3600);
    core.failttl = secs(5);
    let now = Instant::now();
    let req = q("example.org.");
    let k = request_key(&req);
    let p = positive(&req, "example.org. 120 IN A 127.0.0.53");
    core.pcache.add(k, Arc::new(Item::new(&p, now - secs(30), secs(120))));
    let mut f = req.error_reply(ResponseCode::ServFail);
    f.authorities = vec![soa(5)];
    core.ncache.add(k, Arc::new(Item::new(&f, now, secs(5))));
    let got = core.get(now + secs(1), &req, "test", "").unwrap();
    assert_eq!(got.rcode, ResponseCode::NoError);
}

/// TestPreferPositiveCachePolicy.
#[test]
fn prefer_positive_policy() {
    let mut core = CacheCore::new(DEFAULT_CAP, DEFAULT_CAP);
    core.stale_up_to = secs(3600);
    let now = Instant::now();
    let req = q("example.org.");
    let k = request_key(&req);
    let p = positive(&req, "example.org. 60 IN A 192.0.2.1");
    core.pcache.add(k, Arc::new(Item::new(&p, now - 2 * MIN, MIN)));
    core.ncache.add(k, Arc::new(Item::new(&negative(&req), now, 5 * MIN)));
    let got = core.get(now, &req, "test", "").unwrap();
    assert_eq!(got.rcode, ResponseCode::NXDomain, "the default prefers the denial");
    core.prefer_positive = true;
    let got = core.get(now, &req, "test", "").unwrap();
    assert_eq!(got.rcode, ResponseCode::NoError, "prefer_positive prefers the answer");
}

/// TestPreferPositiveRejectsNonAnswer.
#[test]
fn prefer_positive_rejects_non_answer() {
    let mut core = CacheCore::new(DEFAULT_CAP, DEFAULT_CAP);
    core.stale_up_to = secs(3600);
    core.prefer_positive = true;
    let now = Instant::now();
    let req = q("alias.example.org.");
    let k = request_key(&req);
    let p = positive(&req, "alias.example.org. 60 IN CNAME missing.example.org.");
    core.pcache.add(k, Arc::new(Item::new(&p, now, MIN)));
    core.ncache.add(k, Arc::new(Item::new(&negative(&req), now, 5 * MIN)));
    let got = core.get(now, &req, "test", "").unwrap();
    assert_eq!(got.rcode, ResponseCode::NXDomain);
}

/// TestAnswersQuestionStrictEligibility.
#[test]
fn answers_question_strict_eligibility() {
    let mut ch = rr("cached.org. 60 IN A 192.0.2.20");
    ch.dns_class = DNSClass::CH;
    for (name, qtype, answer, want) in [
        (
            "direct A",
            RecordType::A,
            vec![rr("cached.org. 60 IN A 192.0.2.10")],
            true,
        ),
        (
            "ANY matching owner",
            RecordType::ANY,
            vec![rr("cached.org. 60 IN A 192.0.2.10")],
            true,
        ),
        (
            "ANY unrelated owner",
            RecordType::ANY,
            vec![rr("unrelated.org. 60 IN A 192.0.2.10")],
            false,
        ),
        (
            "duplicate equivalent CNAME targets",
            RecordType::CNAME,
            vec![
                rr("cached.org. 60 IN CNAME target.org."),
                rr("cached.org. 60 IN CNAME target.org."),
            ],
            true,
        ),
        (
            "multiple CNAME targets",
            RecordType::CNAME,
            vec![
                rr("cached.org. 60 IN CNAME first.org."),
                rr("cached.org. 60 IN CNAME second.org."),
            ],
            false,
        ),
        ("wrong RR class", RecordType::A, vec![ch.clone()], false),
    ] {
        let req = query("cached.org.", qtype, "10.240.0.1:1");
        let mut m = req.reply();
        m.answers = answer;
        assert_eq!(answers_question(&m), want, "{name}");
    }
}

/// TestPreferPositiveRetainsLKGAcrossNonAnswerSuccessRefreshes.
#[tokio::test]
async fn prefer_positive_retains_lkg() {
    let mut core = CacheCore::new(DEFAULT_CAP, DEFAULT_CAP);
    core.stale_up_to = secs(3600);
    core.prefer_positive = true;
    let req = q("cached.org.");
    let mut w = CacheWriter::new(&core, &req, "test", "");
    w.prefetch = true;
    w.write_msg(positive(&req, "cached.org. 60 IN A 192.0.2.10"))
        .await
        .unwrap();

    core.clock.set(2 * MIN);
    let empty = req.reply();
    let mut referral = req.reply();
    referral.authorities = vec![rr("example.org. 60 IN NS ns.example.org.")];
    let mut glue = referral.clone();
    glue.additionals = vec![rr("ns.example.org. 60 IN A 192.0.2.53")];
    let mut extra = req.reply();
    extra.additionals = vec![rr("cached.org. 60 IN A 192.0.2.54")];
    for (i, refresh) in [empty, referral, glue, extra].into_iter().enumerate() {
        w.write_msg(refresh).await.unwrap();
        let got = core.get(core.clock.now(), &req, "test", "");
        let got = got.unwrap_or_else(|| panic!("refresh {i} lost the last known good answer"));
        assert!(got.answering && got.matches(&req), "refresh {i}");
        assert_eq!(got.answers[0].data, RData::A(A::new(192, 0, 2, 10)), "refresh {i}");
    }
}

/// TestPreferPositiveDoesNotServeLKGOutsideStaleWindow.
#[test]
fn prefer_positive_lkg_outside_stale_window() {
    let mut core = CacheCore::new(DEFAULT_CAP, DEFAULT_CAP);
    core.stale_up_to = secs(3600);
    core.prefer_positive = true;
    let now = Instant::now();
    let req = q("cached.org.");
    let k = request_key(&req);
    let lkg = Item::new(&positive(&req, "cached.org. 60 IN A 192.0.2.10"), now - secs(7200), MIN);
    let mut current = Item::new(&req.reply(), now, MIN);
    current.last_known_good = Some(Arc::new(lkg));
    core.pcache.add(k, Arc::new(current));
    core.ncache.add(k, Arc::new(Item::new(&negative(&req), now, 5 * MIN)));
    let got = core.get(now, &req, "test", "").unwrap();
    assert_eq!(got.rcode, ResponseCode::NXDomain);
}

/// TestPreferPositiveVerifyKeepsStaleOnNonAnswers.
#[tokio::test]
async fn prefer_positive_verify_keeps_stale_on_non_answers() {
    let nodata = func(|r| {
        let mut m = r.reply();
        m.authorities = vec![rr(
            "example.org. 300 IN SOA ns.example.org. hostmaster.example.org. 1 7200 3600 1209600 300",
        )];
        (Some(m), Ok(ResponseCode::NoError))
    });
    let notimp = func(|r| (Some(r.error_reply(ResponseCode::NotImp)), Ok(ResponseCode::NotImp)));
    for (name, backend) in [
        ("NXDOMAIN", nx_backend(300)),
        ("NODATA", nodata),
        ("SERVFAIL", servfail_backend(300)),
        ("NOTIMP", notimp),
    ] {
        let (c, sw) = new_cache(|c| {
            c.stale_up_to = secs(3600);
            c.verify_stale = true;
            c.prefer_positive = true;
        });
        sw.set(ttl_backend(60));
        let req = q("cached.org.");
        let _ = ask(&c, &req).await;
        c.core.clock.set(2 * MIN);
        sw.set(backend);
        let (res, m) = ask(&c, &req).await;
        assert_eq!(res.unwrap(), ResponseCode::NoError, "{name}");
        let m = m.unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError, "{name}");
        assert_eq!(m.answers[0].ttl, 0, "{name}: stale TTL");
        assert_eq!(c.core.ncache.len(), 1, "{name}: the verified denial is cached");
    }
}

const EXPIRED_RRSIG: &str = "cached.org. 60 IN RRSIG A 8 2 60 20160521031301 20160421031301 12051 cached.org. lAaEzB5teQLLKyDenatmyhca7blLRg9DoGNrhe3NReBZN5C5/pMQk8Jc u25hv2fW23/SLm5IC2zaDpp2Fzgm6Jf7e90/yLcwQPuE7JjS55WMF+HE LEh7Z6AEb+Iq4BWmNhUz6gPxD4d9eRMs7EAzk13o1NYi5/JhfL6IlaYy qkc=";

/// Invalid refreshes: an answer with an expired RRSIG (for a DO query),
/// a truncated answer and (`all`) an answer to another question.
fn invalid_refreshes(all: bool) -> Vec<(&'static str, Arc<dyn Handler>)> {
    let mut v: Vec<(&'static str, Arc<dyn Handler>)> = vec![
        (
            "expired RRSIG",
            func(|r| {
                let mut m = r.reply();
                let mut e = Edns::new();
                e.set_max_payload(4096);
                e.set_dnssec_ok(true);
                m.edns = Some(e);
                m.answers = vec![rr("cached.org. 60 IN A 192.0.2.20"), rr(EXPIRED_RRSIG)];
                (Some(m), Ok(ResponseCode::NoError))
            }),
        ),
        (
            "truncated",
            func(|r| {
                let mut m = r.reply();
                m.metadata.truncation = true;
                m.answers = vec![rr("cached.org. 60 IN A 192.0.2.20")];
                (Some(m), Ok(ResponseCode::NoError))
            }),
        ),
    ];
    if all {
        v.push((
            "mismatched question",
            func(|r| {
                let mut m = query("other.org.", RecordType::A, "10.240.0.1:1").reply();
                m.metadata.id = r.msg.metadata.id;
                m.answers = vec![rr("other.org. 60 IN A 192.0.2.20")];
                (Some(m), Ok(ResponseCode::NoError))
            }),
        ));
    }
    v
}

/// TestPreferPositiveVerifyRejectsInvalidFreshAnswers.
#[tokio::test]
async fn prefer_positive_verify_rejects_invalid_fresh_answers() {
    for (mode, timeout) in [("blocking", Duration::ZERO), ("bounded", secs(1))] {
        for (name, invalid) in invalid_refreshes(false) {
            let (c, sw) = new_cache(|c| {
                c.stale_up_to = secs(3600);
                c.verify_stale = true;
                c.verify_stale_timeout = timeout;
                c.prefer_positive = true;
            });
            sw.set(func(|r| {
                (
                    Some(positive(r, "cached.org. 60 IN A 192.0.2.10")),
                    Ok(ResponseCode::NoError),
                )
            }));
            let req = with_do(q("cached.org."));
            ask(&c, &req).await.0.unwrap();
            c.core.clock.set(2 * MIN);
            sw.set(invalid);
            let (res, m) = ask(&c, &req).await;
            assert_eq!(res.unwrap(), ResponseCode::NoError, "{mode}/{name}");
            let m = m.unwrap();
            assert_eq!(m.metadata.response_code, ResponseCode::NoError, "{mode}/{name}");
            assert_eq!(a_of(&m), ("192.0.2.10".into(), 0), "{mode}/{name}");
        }
    }
}

/// TestCNAMEWithSOAStoredAsNODATA.
#[tokio::test]
async fn cname_with_soa_stored_as_nodata() {
    let core = CacheCore::new(DEFAULT_CAP, DEFAULT_CAP);
    let req = q("alias.example.org.");
    let mut w = CacheWriter::new(&core, &req, "test", "");
    w.prefetch = true;
    let mut m = positive(&req, "alias.example.org. 300 IN CNAME missing.example.net.");
    m.authorities = vec![rr(
        "example.org. 300 IN SOA ns.example.org. hostmaster.example.org. 1 7200 3600 1209600 300",
    )];
    w.write_msg(m).await.unwrap();
    assert_eq!(core.ncache.len(), 1);
    assert_eq!(core.pcache.len(), 0);
}

/// TestKeyEmptyQuestion.
#[test]
fn key_empty_question() {
    let m = Message::new(0, kerndns_core::proto::op::MessageType::Response, OpCode::Query);
    assert!(cache_key("example.org.", &m, ResponseType::NoError, false, false).is_none());
}

// --- prefetch_test.go ---

/// TestPrefetch.
#[tokio::test]
async fn prefetch() {
    struct V {
        after: u64,
        answer: (&'static str, u32, &'static str),
        do_bit: bool,
        cd: bool,
        fetch: bool,
    }
    let v = |after, ttl, ip, fetch| V {
        after,
        answer: ("", ttl, ip),
        do_bit: false,
        cd: false,
        fetch,
    };
    let tests: Vec<(&str, u32, u32, Vec<V>)> = vec![
        (
            "hits.reset.example.org.",
            80,
            1,
            vec![
                v(0, 80, "127.0.0.1", true),
                // 10% of 80 is 8: a prefetch at TTL 7
                v(73, 7, "127.0.0.1", true),
                v(80, 73, "127.0.0.2", false),
            ],
        ),
        (
            "short.ttl.example.org.",
            5,
            1,
            vec![
                v(0, 5, "127.0.0.1", true),
                v(1, 4, "127.0.0.1", false),
                v(4, 1, "127.0.0.1", true),
                v(5, 4, "127.0.0.2", false),
            ],
        ),
        (
            "no.prefetch.example.org.",
            30,
            0,
            vec![
                v(0, 30, "127.0.0.1", true),
                v(15, 15, "127.0.0.1", false),
                v(29, 1, "127.0.0.1", false),
                v(30, 30, "127.0.0.2", true),
            ],
        ),
        (
            // the prefetch keeps the DO bit
            "do.prefetch.example.org.",
            80,
            1,
            vec![
                V {
                    do_bit: true,
                    ..v(0, 80, "127.0.0.1", true)
                },
                V {
                    do_bit: true,
                    ..v(73, 7, "127.0.0.1", true)
                },
                V {
                    do_bit: true,
                    ..v(80, 73, "127.0.0.2", false)
                },
                v(80, 80, "127.0.0.3", true),
            ],
        ),
        (
            // the prefetch keeps the CD bit
            "cd.prefetch.example.org.",
            80,
            1,
            vec![
                V {
                    cd: true,
                    ..v(0, 80, "127.0.0.1", true)
                },
                V {
                    cd: true,
                    ..v(73, 7, "127.0.0.1", true)
                },
                V {
                    cd: true,
                    ..v(80, 73, "127.0.0.2", false)
                },
                v(80, 80, "127.0.0.3", true),
            ],
        ),
    ];
    for (qname, ttl, amount, verifications) in tests {
        let (c, sw) = new_cache(|c| c.prefetch = amount);
        // prefetchHandler: one A record, 127.0.0.N for the Nth call
        let (tx, mut fetched) = mpsc::unbounded_channel();
        let n = Arc::new(AtomicU32::new(0));
        sw.set(func(move |r| {
            let i = n.fetch_add(1, Ordering::SeqCst) + 1;
            let mut m = r.reply();
            m.answers = vec![rr(&format!("{qname} {ttl} IN A 127.0.0.{i}"))];
            let _ = tx.send(());
            (Some(m), Ok(ResponseCode::NoError))
        }));
        for v in verifications {
            c.core.clock.set(secs(v.after));
            let mut req = q(qname);
            req.msg.metadata.checking_disabled = v.cd;
            let mut e = Edns::new();
            e.set_max_payload(512);
            e.set_dnssec_ok(v.do_bit);
            req.msg.edns = Some(e);
            let (res, m) = ask(&c, &req).await;
            if v.fetch {
                tokio::time::timeout(secs(1), fetched.recv())
                    .await
                    .unwrap_or_else(|_| panic!("{qname} after {}s: want a fetch", v.after));
            }
            assert_eq!(res.unwrap(), ResponseCode::NoError);
            let m = m.unwrap();
            assert_eq!(m.answers.len(), 1);
            assert_eq!(
                a_of(&m),
                (v.answer.2.to_string(), v.answer.1),
                "{qname} after {}s",
                v.after
            );
            // let a prefetch store its answer before the clock moves on
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// TestPrefetchDedup: concurrent hits on one item start one refresh, on
/// the serve_stale and the prefetch paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prefetch_dedup() {
    for (name, stale, amount, percentage, hit_at) in [
        ("serve_stale", secs(3600), 0, 10, secs(110)),
        ("prefetch", Duration::ZERO, 1, 50, secs(70)),
    ] {
        let (c, sw) = new_cache(|c| {
            c.stale_up_to = stale;
            c.prefetch = amount;
            c.percentage = percentage;
        });
        let upstream = Arc::new(AtomicU32::new(0));
        let release = Arc::new(Semaphore::new(0));
        let (done_tx, mut done) = mpsc::unbounded_channel();
        struct Dedup(Arc<AtomicU32>, Arc<Semaphore>, mpsc::UnboundedSender<()>);
        #[async_trait]
        impl Handler for Dedup {
            fn name(&self) -> &'static str {
                "dedup"
            }
            async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
                let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
                if n > 1 {
                    let _ = self.1.acquire().await.map(|p| p.forget());
                }
                let mut m = req.reply();
                m.answers = vec![rr("dedup.example.org. 100 IN A 127.0.0.1")];
                let _ = w.write_msg(m).await;
                if n > 1 {
                    let _ = self.2.send(());
                }
                Ok(ResponseCode::NoError)
            }
        }
        sw.set(Arc::new(Dedup(upstream.clone(), release.clone(), done_tx)));
        let _ = ask(&c, &q("dedup.example.org.")).await;
        assert_eq!(upstream.load(Ordering::SeqCst), 1, "{name}: initial populate");
        c.core.clock.set(hit_at);
        let tasks: Vec<_> = (0..200)
            .map(|_| {
                let c = c.clone();
                tokio::spawn(async move {
                    let _ = ask(&c, &q("dedup.example.org.")).await;
                })
            })
            .collect();
        for t in tasks {
            t.await.unwrap();
        }
        release.close();
        signal(&mut done, "prefetch never completed").await;
        assert_eq!(
            upstream.load(Ordering::SeqCst),
            2,
            "{name}: populate + 1 deduplicated prefetch"
        );
    }
}

// --- serve_stale_recheck_test.go ---

fn exists(c: &Cache, req: &Request) -> Arc<Item> {
    c.core.exists(req).expect("a cached item")
}

/// TestServeStaleFailureRecheckImmediate.
#[tokio::test]
async fn failure_recheck_immediate() {
    for (name, prime, want) in [
        ("positive", ttl_backend(1), ResponseCode::NoError),
        ("negative", nx_backend(1), ResponseCode::NXDomain),
    ] {
        let (c, sw) = new_cache(|c| {
            c.minpttl = Duration::ZERO;
            c.minnttl = Duration::ZERO;
            c.stale_up_to = secs(3600);
            c.stale_ttl = 30;
            c.stale_recheck = secs(30);
        });
        sw.set(prime);
        let req = q("cached.org.");
        let _ = ask(&c, &req).await;
        let item = exists(&c, &req);

        c.core.clock.set(secs(2));
        let (h, mut g) = gated(servfail_backend(30));
        sw.set(h);
        let (_, m) = ask(&c, &req).await;
        assert_eq!(m.unwrap().metadata.response_code, want, "{name}: stale rcode");
        signal(&mut g.started, "background refresh did not start").await;
        g.release.add_permits(1);
        wait_refresh(&mut g.completed, &item).await;
        assert_eq!(g.calls(), 1, "{name}");

        let (_, m) = ask(&c, &req).await;
        assert_eq!(m.unwrap().metadata.response_code, want, "{name}: during recheck");
        assert!(
            !item.refreshing.load(Ordering::Acquire),
            "{name}: the recheck suppresses a refresh"
        );
        assert_eq!(g.calls(), 1, "{name}: refresh suppressed during recheck");

        c.core.clock.set(secs(33));
        let _ = ask(&c, &req).await;
        signal(&mut g.started, "refresh did not restart after the recheck").await;
        g.release.add_permits(1);
        wait_refresh(&mut g.completed, &item).await;
        assert_eq!(g.calls(), 2, "{name}");
        assert_eq!(
            exists(&c, &req).rcode,
            want,
            "{name}: a failed refresh keeps the stale entry"
        );
    }
}

/// A servfail backend counting its calls.
fn counted_servfail(calls: &Arc<AtomicU32>) -> Arc<dyn Handler> {
    let (calls, inner) = (calls.clone(), servfail_backend(30));
    struct Counted(Arc<AtomicU32>, Arc<dyn Handler>);
    #[async_trait]
    impl Handler for Counted {
        fn name(&self) -> &'static str {
            "counted"
        }
        async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
            self.0.fetch_add(1, Ordering::SeqCst);
            self.1.serve_dns(ctx, w, req).await
        }
    }
    Arc::new(Counted(calls, inner))
}

fn recheck_cache(f: impl FnOnce(&mut CacheCore)) -> (Arc<Cache>, Switch) {
    new_cache(|c| {
        c.minpttl = Duration::ZERO;
        c.minnttl = Duration::ZERO;
        c.stale_up_to = secs(3600);
        c.verify_stale = true;
        f(c)
    })
}

/// TestServeStaleFailureRecheckVerify.
#[tokio::test]
async fn failure_recheck_verify() {
    let (c, sw) = recheck_cache(|c| c.stale_recheck = secs(30));
    sw.set(ttl_backend(1));
    let req = q("cached.org.");
    let _ = ask(&c, &req).await;
    c.core.clock.set(secs(2));
    let calls = Arc::new(AtomicU32::new(0));
    sw.set(counted_servfail(&calls));
    let _ = ask(&c, &req).await;
    let _ = ask(&c, &req).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one verify during the failure recheck");
    c.core.clock.set(secs(33));
    let _ = ask(&c, &req).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2, "a verify after the recheck");
}

/// TestServeStaleFailureRecheckRejectsInvalidRefresh.
#[tokio::test]
async fn failure_recheck_rejects_invalid_refresh() {
    for (mode, verify) in [("immediate", false), ("verify", true)] {
        for (name, invalid) in invalid_refreshes(true) {
            let (c, sw) = new_cache(|c| {
                c.minpttl = Duration::ZERO;
                c.stale_up_to = secs(3600);
                c.verify_stale = verify;
                c.stale_ttl = 30;
                c.stale_recheck = secs(30);
            });
            sw.set(ttl_backend(1));
            let req = with_do(q("cached.org."));
            let _ = ask(&c, &req).await;
            let item = exists(&c, &req);
            c.core.clock.set(secs(2));
            let (h, mut g) = gated(invalid);
            g.release.close();
            sw.set(h);

            let (_, m) = ask(&c, &req).await;
            assert_eq!(a_of(&m.unwrap()), ("127.0.0.53".into(), 30), "{mode}/{name}");
            wait_refresh(&mut g.completed, &item).await;
            let r = item.retry_after.load(Ordering::Acquire);
            assert!(
                r != 0 && item.stored + Duration::from_nanos(r) > c.core.clock.now(),
                "{mode}/{name}: the invalid refresh starts the failure recheck"
            );
            let (_, m) = ask(&c, &req).await;
            assert_eq!(a_of(&m.unwrap()), ("127.0.0.53".into(), 30), "{mode}/{name}");
            assert_eq!(g.calls(), 1, "{mode}/{name}: refresh suppressed during the recheck");
        }
    }
}

/// TestServeStaleFailureRecheckVerifyTimeoutCoalesces.
#[tokio::test]
async fn failure_recheck_verify_timeout_coalesces() {
    let (c, sw) = recheck_cache(|c| {
        c.verify_stale_timeout = Duration::from_millis(10);
        c.stale_recheck = secs(30);
    });
    sw.set(ttl_backend(1));
    let req = q("cached.org.");
    let _ = ask(&c, &req).await;
    let item = exists(&c, &req);
    c.core.clock.set(secs(2));
    let (h, mut g) = gated(servfail_backend(30));
    sw.set(h);

    let _ = ask(&c, &req).await;
    signal(&mut g.started, "background verify did not start").await;
    let _ = ask(&c, &req).await;
    assert_eq!(g.calls(), 1, "concurrent stale requests share the verify");

    g.release.close();
    wait_refresh(&mut g.completed, &item).await;
    let _ = ask(&c, &req).await;
    assert_eq!(g.calls(), 1, "the failed verify starts the recheck delay");

    c.core.clock.set(secs(33));
    let _ = ask(&c, &req).await;
    wait_refresh(&mut g.completed, &item).await;
    assert_eq!(g.calls(), 2, "a new verify after the recheck");
}

/// TestServeStaleVerifyTimeoutCoalescesWithoutFailureRecheck.
#[tokio::test]
async fn verify_timeout_coalesces_without_failure_recheck() {
    let (c, sw) = recheck_cache(|c| c.verify_stale_timeout = Duration::from_millis(10));
    sw.set(ttl_backend(1));
    let req = q("cached.org.");
    let _ = ask(&c, &req).await;
    let item = exists(&c, &req);
    c.core.clock.set(secs(2));
    let (h, mut g) = gated(servfail_backend(30));
    sw.set(h);
    let _ = ask(&c, &req).await;
    signal(&mut g.started, "background verify did not start").await;
    let _ = ask(&c, &req).await;
    assert_eq!(g.calls(), 1, "concurrent stale requests share the verify");
    g.release.add_permits(1);
    wait_refresh(&mut g.completed, &item).await;
}

/// TestServeStaleFailureRecheckDisabledPreservesVerifyBehavior.
#[tokio::test]
async fn failure_recheck_disabled_preserves_verify() {
    let (c, sw) = recheck_cache(|_| {});
    sw.set(ttl_backend(1));
    let req = q("cached.org.");
    let _ = ask(&c, &req).await;
    c.core.clock.set(secs(2));
    let calls = Arc::new(AtomicU32::new(0));
    sw.set(counted_servfail(&calls));
    let _ = ask(&c, &req).await;
    let _ = ask(&c, &req).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2, "every request verifies");
}

/// `coredns_cache_served_stale_total` counts stale answers, not verified ones.
#[tokio::test]
async fn served_stale_metric() {
    let (c, sw) = new_cache(|c| {
        c.zones_label = "served-stale-metric.".into();
        c.stale_up_to = secs(3600);
        c.verify_stale = true;
    });
    let count = || {
        pm::CACHE_SERVED_STALE
            .with_label_values(&["dns://:53", "served-stale-metric.", ""])
            .get()
    };
    sw.set(ttl_backend(60));
    let req = q("cached.org.");
    let _ = ask(&c, &req).await;
    c.core.clock.set(2 * MIN);
    sw.set(servfail_backend(60));
    let _ = ask(&c, &req).await;
    assert_eq!(count(), 1.0);
    sw.set(ttl_backend(60));
    let _ = ask(&c, &req).await;
    assert_eq!(count(), 1.0, "a verified refresh isn't stale");
}

/// The cache's view label comes from the request's view.
#[tokio::test]
async fn view_label() {
    let (c, sw) = new_cache(|c| c.zones_label = "view-label.".into());
    sw.set(ttl_backend(60));
    let mut ctx = Context::new(".", "dns://:53");
    ctx.view = Some("v1".into());
    let mut w = CaptureWriter::new();
    c.serve_dns(&mut ctx, &mut w, &q("cached.org.")).await.unwrap();
    let n = pm::CACHE_REQUESTS
        .with_label_values(&["dns://:53", "view-label.", "v1"])
        .get();
    assert_eq!(n, 1.0);
}
