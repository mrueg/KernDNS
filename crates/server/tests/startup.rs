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

/// What the slow startup hook of the new configuration saw.
#[derive(Debug, PartialEq)]
struct DuringReload {
    /// The listener's answer meanwhile (the old chain's).
    rcode: Option<ResponseCode>,
    old_restarted: bool,
    old_shut_down: bool,
}

/// `whoami old` answers NOERROR, `whoami new` NXDOMAIN. The new
/// configuration's startup hook queries the server and takes a while.
struct Generations {
    port: u16,
    restarted: Arc<AtomicBool>,
    shut_down: Arc<AtomicBool>,
    seen: std::sync::mpsc::Sender<DuringReload>,
}

struct Answer(ResponseCode);

#[async_trait]
impl Handler for Answer {
    fn name(&self) -> &'static str {
        "whoami"
    }

    async fn serve_dns(&self, _: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        w.write_msg(req.error_reply(self.0))
            .await
            .map_err(|e| PluginError::servfail("whoami", e.to_string()))?;
        Ok(ResponseCode::NoError)
    }
}

impl PluginFactory for Generations {
    fn name(&self) -> &'static str {
        "whoami"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        c.next();
        let new = c.remaining_args().first().is_some_and(|a| a == "new");
        if new {
            let (port, restarted, shut_down, seen) = (
                self.port,
                self.restarted.clone(),
                self.shut_down.clone(),
                self.seen.clone(),
            );
            c.on_startup(move || {
                let rcode = udp_query(port);
                std::thread::sleep(Duration::from_millis(300));
                let _ = seen.send(DuringReload {
                    rcode,
                    old_restarted: restarted.load(Ordering::SeqCst),
                    old_shut_down: shut_down.load(Ordering::SeqCst),
                });
                Ok(())
            });
        } else {
            let r = self.restarted.clone();
            c.on_restart(move || {
                r.store(true, Ordering::SeqCst);
                Ok(())
            });
            let s = self.shut_down.clone();
            c.on_shutdown(move || s.store(true, Ordering::SeqCst));
        }
        let rcode = if new {
            ResponseCode::NXDomain
        } else {
            ResponseCode::NoError
        };
        c.add_plugin(move |_| Arc::new(Answer(rcode)));
        Ok(())
    }
}

/// caddy's `Instance.Restart` order: the old configuration's `OnRestart`
/// hooks, then the new one's `OnStartup` hooks while the old chain still
/// answers and before the old `OnShutdown` hooks; new listeners serve once
/// the hooks are done.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reload_runs_new_startup_hooks_while_old_config_serves() {
    let free = || UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (port, port2) = (free(), free());
    let (tx, rx) = std::sync::mpsc::channel();
    let shut_down = Arc::new(AtomicBool::new(false));
    let mut registry = Registry::new();
    registry.register(Generations {
        port,
        restarted: Arc::default(),
        shut_down: shut_down.clone(),
        seen: tx,
    });
    let opts = Options::default();
    let old = format!(".:{port} {{\n whoami old\n}}\n");
    let mut inst = Instance::start(&old, "Corefile", &registry, &opts).await.unwrap();
    let q = |p| tokio::task::spawn_blocking(move || udp_query(p));
    assert_eq!(q(port).await.unwrap(), Some(ResponseCode::NoError));

    let new = format!(".:{port} {{\n whoami new\n}}\n.:{port2} {{\n whoami new\n}}\n");
    let plan = kerndns_server::load(&new, "Corefile", &registry, &opts).unwrap();
    inst.reload(plan).await.unwrap();
    let seen = rx
        .recv_timeout(Duration::from_secs(1))
        .expect("the new startup hook ran");
    assert_eq!(
        seen,
        DuringReload {
            rcode: Some(ResponseCode::NoError),
            old_restarted: true,
            old_shut_down: false,
        }
    );
    assert!(
        shut_down.load(Ordering::SeqCst),
        "the old shutdown hooks ran after the switch"
    );
    assert_eq!(q(port).await.unwrap(), Some(ResponseCode::NXDomain));
    assert_eq!(
        q(port2).await.unwrap(),
        Some(ResponseCode::NXDomain),
        "the new listener serves"
    );
    inst.stop().await;
}
