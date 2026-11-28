//! Queries must not reach a plugin before its startup hook has run:
//! CoreDNS (caddy) runs the `OnStartup` hooks before it starts serving,
//! e.g. `hosts` reads its file there. KernDNS binds the listeners first;
//! a query that arrives during the hooks has to wait for them.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, PluginError, PluginFactory, Registry, Request, ResponseWriter,
    SetupError, async_trait,
};
use kerndns_server::{Instance, Options};

/// Answers SERVFAIL until its startup hook has run, NOERROR after. The
/// hook queries the server itself and takes a while to finish.
struct SlowStart {
    port: u16,
    rcode: std::sync::mpsc::Sender<Option<ResponseCode>>,
}

struct SlowStartHandler(Arc<AtomicBool>);

#[async_trait]
impl Handler for SlowStartHandler {
    fn name(&self) -> &'static str {
        "whoami"
    }

    async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let rcode = if self.0.load(Ordering::SeqCst) {
            ResponseCode::NoError
        } else {
            ResponseCode::ServFail
        };
        w.write_msg(req.error_reply(rcode))
            .await
            .map_err(|e| PluginError::servfail("whoami", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

fn udp_query(port: u16) -> Option<ResponseCode> {
    let s = UdpSocket::bind("127.0.0.1:0").ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut m = Message::new(4242, MessageType::Query, OpCode::Query);
    m.add_query(Query::query(Name::from_ascii("example.org.").unwrap(), RecordType::A));
    s.send_to(&m.to_vec().ok()?, SocketAddr::from(([127, 0, 0, 1], port)))
        .ok()?;
    let mut buf = [0u8; 512];
    let n = s.recv(&mut buf).ok()?;
    Some(Message::from_vec(&buf[..n]).ok()?.metadata.response_code)
}

impl PluginFactory for SlowStart {
    fn name(&self) -> &'static str {
        "whoami"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        while c.next() {}
        let started = Arc::new(AtomicBool::new(false));
        let (s, port, tx) = (started.clone(), self.port, self.rcode.clone());
        c.on_startup(move || {
            // the listener is bound by now: this query arrives during the hook
            std::thread::spawn(move || tx.send(udp_query(port)));
            std::thread::sleep(Duration::from_millis(300));
            s.store(true, Ordering::SeqCst);
            Ok(())
        });
        c.add_plugin(move |_| Arc::new(SlowStartHandler(started.clone())));
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queries_wait_for_startup_hooks() {
    let port = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    let mut registry = Registry::new();
    registry.register(SlowStart { port, rcode: tx });
    let corefile = format!(".:{port} {{\n whoami\n}}\n");
    let _inst = Instance::start(&corefile, "Corefile", &registry, &Options::default())
        .await
        .unwrap_or_else(|e| panic!("start: {e}"));
    let rcode = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(10)))
        .await
        .unwrap()
        .expect("the hook's query finished");
    assert_eq!(
        rcode,
        Some(ResponseCode::NoError),
        "query answered before the startup hook ran"
    );
}
