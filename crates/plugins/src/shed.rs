//! `shed`: one writer per UDP socket and load shedding when it can't keep
//! up. Port of `plugin/shed`.
//!
//! ```text
//! shed
//! ```
//!
//! Responses on a plain DNS UDP socket are not sent by the task that
//! answered the query: they are pushed onto a bounded stack (depth 1024)
//! per socket, and one writer task per socket sends them, newest first,
//! evicting the oldest when the stack is full. While a socket's stack is
//! full, queries arriving on it are dropped before any plugin runs. Every
//! drop is counted in `coredns_shed_dropped_total{server, reason}`.
//!
//! CoreDNS added this to keep Go's per-socket write mutex from overflowing
//! (a runtime panic). Tokio has no such limit, but the plugin bounds the
//! same thing: work admitted for a socket that can't send it fast enough.
//! The listener installs the writer when it binds the socket (CoreDNS's
//! `UDPDecorateWriterFunc`), so adding or removing `shed` takes effect at
//! a restart, not on reload.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::udpwrite::{UdpDecorator, UdpWriter, WriterTask};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, Transport,
    async_trait, next_or_failure,
};
use prometheus::Counter;
use tokio::net::UdpSocket;
use tokio::sync::Notify;

use crate::pluginmetrics as pm;

const NAME: &str = "shed";

/// A burst budget, not a knob (CoreDNS's `stackDepth`).
const STACK_DEPTH: usize = 1024;

/// A bounded stack that evicts its oldest entry when full and pops the
/// newest first (`respStack`).
struct RespStack<T> {
    buf: Mutex<VecDeque<T>>,
    depth: usize,
    /// Mirror of the length for the lock-free [`full`](Self::full) check.
    n: AtomicUsize,
    notify: Notify,
}

impl<T> RespStack<T> {
    fn new(depth: usize) -> Self {
        RespStack {
            buf: Mutex::new(VecDeque::with_capacity(depth)),
            depth,
            n: AtomicUsize::new(0),
            notify: Notify::new(),
        }
    }

    /// Add `p` as the newest entry, evicting the oldest when full. Never
    /// blocks. Reports whether an entry was evicted.
    fn push(&self, p: T) -> bool {
        let dropped = {
            let mut buf = self.buf.lock().unwrap();
            let dropped = buf.len() == self.depth && buf.pop_front().is_some();
            buf.push_back(p);
            self.n.store(buf.len(), Ordering::Relaxed);
            dropped
        };
        self.notify.notify_one();
        dropped
    }

    /// Remove and return the newest entry.
    fn pop(&self) -> Option<T> {
        let mut buf = self.buf.lock().unwrap();
        let p = buf.pop_back();
        self.n.store(buf.len(), Ordering::Relaxed);
        p
    }

    /// A racy read by design: a load-shedding heuristic.
    fn full(&self) -> bool {
        self.n.load(Ordering::Relaxed) >= self.depth
    }

    /// Wait until there is something to pop.
    async fn wait_nonempty(&self) {
        while self.n.load(Ordering::Relaxed) == 0 {
            self.notify.notified().await;
        }
    }
}

/// One UDP socket's state: its stack and drop counters (`socketState`).
struct SocketState {
    stack: RespStack<(Vec<u8>, SocketAddr)>,
    dropped_response: Counter,
    dropped_query: Counter,
}

impl UdpWriter for SocketState {
    /// "Written" means queued for the socket's writer task.
    fn write(&self, data: Vec<u8>, dst: SocketAddr) {
        if self.stack.push((data, dst)) {
            self.dropped_response.inc();
        }
    }

    fn full(&self) -> bool {
        self.stack.full()
    }

    fn drop_query(&self) {
        self.dropped_query.inc();
    }
}

/// The socket's single writer: pops the newest response and sends it; a
/// response that fails to reach the wire is a counted drop.
async fn writer_loop(st: Arc<SocketState>, sock: Arc<UdpSocket>) {
    loop {
        st.stack.wait_nonempty().await;
        if let Some((data, dst)) = st.stack.pop()
            && let Err(e) = sock.send_to(&data, dst).await
        {
            st.dropped_response.inc();
            kerndns_core::debug!(plugin = NAME, "Deferred response write failed: {e}");
        }
    }
}

/// Installs the stack and writer on each UDP socket
/// (`decorateWriterFactory`).
struct Decorator;

impl UdpDecorator for Decorator {
    fn decorate(&self, server: &str, sock: Arc<UdpSocket>) -> (Arc<dyn UdpWriter>, WriterTask) {
        let st = Arc::new(SocketState {
            stack: RespStack::new(STACK_DEPTH),
            dropped_response: pm::SHED_DROPPED.with_label_values(&[server, "response"]),
            dropped_query: pm::SHED_DROPPED.with_label_values(&[server, "query"]),
        });
        let task = Box::pin(writer_loop(st.clone(), sock));
        (st, task)
    }
}

/// The handler: drops UDP queries while the socket's stack is full.
pub struct Shed {
    next: Next,
}

#[async_trait]
impl Handler for Shed {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        // UDP only: TCP must never be starved by UDP-storm shedding
        if req.proto() != "udp" {
            return next_or_failure(NAME, &self.next, ctx, w, req).await;
        }
        // no decorated socket (e.g. an internal lookup): fail open
        let Some(st) = &req.conn.udp_writer else {
            return next_or_failure(NAME, &self.next, ctx, w, req).await;
        };
        if st.full() {
            // silent drop: nothing is written, and NOERROR keeps the
            // server from writing an error response
            st.drop_query();
            return Ok(ResponseCode::NoError);
        }
        next_or_failure(NAME, &self.next, ctx, w, req).await
    }
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut i = 0;
        while c.next() {
            if i > 0 {
                return Err(SetupError::new(
                    NAME,
                    "this plugin can only be used once per Server Block",
                ));
            }
            i += 1;
            if !c.remaining_args().is_empty() {
                return Err(c.arg_err());
            }
            if c.next_block() {
                return Err(c.errf("shed takes no options"));
            }
        }
        // only the plain DNS UDP path can be decorated
        if let Some(k) = c.config.keys.iter().find(|k| k.transport != Transport::Dns) {
            let msg = format!(
                "only plain DNS server blocks are supported; \"{}://{}:{}\" uses transport \"{}\"",
                k.transport, k.zone, k.port, k.transport
            );
            return Err(c.errf(msg));
        }
        c.config.udp_decorator = Some(Arc::new(Decorator));
        c.add_plugin(|next| Arc::new(Shed { next }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use kerndns_core::corefile::{Dispenser, parse};
    use kerndns_core::proto::rr::RecordType;
    use kerndns_core::{BlockConfig, CaptureWriter, Hooks, Protocol, ZoneAddr};

    fn setup_with_key(key: &str) -> Result<(), String> {
        let blocks = parse(&format!("{key} {{\nshed\n}}"), "Corefile").unwrap();
        let mut cfg = BlockConfig::new(ZoneAddr::parse(key, "53").unwrap());
        let mut hooks = Hooks::default();
        let mut c = Controller::new(
            NAME,
            Dispenser::new(blocks[0].tokens_for(NAME)),
            &mut cfg,
            &mut hooks,
            ".".into(),
        );
        Setup.setup(&mut c).map_err(|e| e.to_string())
    }

    // setup_test.go: TestSetup
    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "shed"));
        let (_, cfg) = run_setup(&Setup, "shed");
        assert!(cfg.udp_decorator.is_some());
        assert_eq!(
            setup_err(&Setup, "shed extra"),
            "plugin/shed: Corefile:2 - Error during parsing: Wrong argument count or unexpected line ending after 'extra'"
        );
        assert_eq!(
            setup_err(&Setup, "shed {\n depth 10\n}"),
            "plugin/shed: Corefile:3 - Error during parsing: shed takes no options"
        );
        assert_eq!(
            setup_err(&Setup, "shed\nshed"),
            "plugin/shed: this plugin can only be used once per Server Block"
        );
    }

    // setup_test.go: TestSetupRejectsNonDNSTransport, TestSetupAcceptsPlainDNSKeys
    #[test]
    fn setup_transports() {
        for key in ["tls://.:853", "grpc://.:443", "https://.:443", "quic://.:853"] {
            let e = setup_with_key(key).expect_err(key);
            assert!(e.contains("plain DNS"), "{key}: {e}");
        }
        assert_eq!(
            setup_with_key("tls://.:853").unwrap_err(),
            "plugin/shed: Corefile:2 - Error during parsing: only plain DNS server blocks are supported; \"tls://.:853\" uses transport \"tls\""
        );
        assert!(setup_with_key("example.org.:53 dns://.:53").is_ok());
    }

    // stack_test.go: TestStackEvictsOldestPopsNewest
    #[test]
    fn stack_evicts_oldest_pops_newest() {
        let rs = RespStack::new(3);
        for i in 1..=5u8 {
            assert_eq!(rs.push(i), i > 3, "push {i}");
        }
        assert!(rs.full());
        for want in [5, 4, 3] {
            assert_eq!(rs.pop(), Some(want));
        }
        assert_eq!(rs.pop(), None);
        assert!(!rs.full());
    }

    fn state(server: &str, depth: usize) -> Arc<SocketState> {
        Arc::new(SocketState {
            stack: RespStack::new(depth),
            dropped_response: pm::SHED_DROPPED.with_label_values(&[server, "response"]),
            dropped_query: pm::SHED_DROPPED.with_label_values(&[server, "query"]),
        })
    }

    // stack_test.go: TestDecoratorCapturesWriteAndWriterWrites
    #[tokio::test]
    async fn decorator_writes_through_the_writer() {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server = "dns://shed-test-decorator:53";
        let (w, task) = Decorator.decorate(server, sock);
        let h = tokio::spawn(task);
        w.write(b"hello".to_vec(), client.local_addr().unwrap());
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.recv(&mut buf))
            .await
            .expect("the writer task sends")
            .unwrap();
        assert_eq!(&buf[..n], b"hello");
        // both series exist from the start (TestShed scrapes them at 0)
        assert_eq!(pm::SHED_DROPPED.with_label_values(&[server, "query"]).get(), 0.0);
        assert_eq!(pm::SHED_DROPPED.with_label_values(&[server, "response"]).get(), 0.0);
        h.abort();
    }

    #[test]
    fn eviction_is_counted() {
        let st = state("dns://shed-test-evict:53", 2);
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        for _ in 0..3 {
            st.write(vec![0], dst);
        }
        assert_eq!(st.dropped_response.get(), 1.0);
    }

    fn handler() -> Shed {
        Shed {
            next: reply(|r: &Request| r.reply()),
        }
    }

    fn udp_request(writer: Option<Arc<SocketState>>, protocol: Protocol) -> Request {
        let mut r = query("example.org.", RecordType::A, "127.0.0.1:4242");
        r.protocol = protocol;
        r.conn.udp_writer = writer.map(|w| w as Arc<dyn UdpWriter>);
        r
    }

    // shed_test.go: TestNoServerInContextFailsOpen, TestUnregisteredSocketFailsOpen
    #[tokio::test]
    async fn no_writer_fails_open() {
        let (rc, w) = serve(&handler(), &udp_request(None, Protocol::Udp)).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        assert!(w.written());
    }

    // shed_test.go: TestTCPPassesThrough
    #[tokio::test]
    async fn tcp_passes_through() {
        let st = state("dns://shed-test-tcp:53", 1);
        st.write(vec![0], "127.0.0.1:9".parse().unwrap());
        assert!(st.full());
        let (_, w) = serve(&handler(), &udp_request(Some(st.clone()), Protocol::Tcp)).await;
        assert!(w.written());
        assert_eq!(st.dropped_query.get(), 0.0);
    }

    // shed_test.go: TestCoupledShedWhenStackFull, TestPassesThroughWhenNotFull
    #[tokio::test]
    async fn coupled_shed() {
        let st = state("dns://shed-test-full:53", 1);
        let req = udp_request(Some(st.clone()), Protocol::Udp);
        let (rc, w) = serve(&handler(), &req).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        assert!(w.written(), "not full: passes through");

        st.write(vec![0], "127.0.0.1:9".parse().unwrap());
        let mut w = CaptureWriter::new();
        let mut ctx = Context::new(".", "dns://:53");
        let rc = handler().serve_dns(&mut ctx, &mut w, &req).await;
        assert_eq!(rc.unwrap(), ResponseCode::NoError);
        assert!(!w.written(), "full: dropped silently");
        assert_eq!(st.dropped_query.get(), 1.0);
    }
}
