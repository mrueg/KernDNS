//! `loop`: detects forwarding loops at startup by sending a random query to
//! itself; if it comes back more than twice, the process exits. Port of
//! `plugin/loop`.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::{Name, RecordType};
use kerndns_core::random::rand_id;
use kerndns_core::zones::{is_subdomain, normalize_exact};
use kerndns_core::{
    Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError, async_trait,
    next_or_failure,
};

pub struct Setup;

struct State {
    zone: String,
    qname: String,
    seen: AtomicU32,
    off: AtomicBool,
    addr: Mutex<String>,
}

fn random_label() -> String {
    // a random 62-bit integer, like CoreDNS's secureRandIntString()
    (rand::random::<u64>() >> 2).to_string()
}

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "loop"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let mut zone = ".".to_string();
        let mut seen = false;
        while c.next() {
            if seen {
                return Err(SetupError::new(
                    "loop",
                    "this plugin can only be used once per Server Block",
                ));
            }
            seen = true;
            if c.next_arg() {
                return Err(c.arg_err());
            }
            if let Some(k) = c.server_block_keys().first()
                && let Some(z) = normalize_exact(k).into_iter().next()
            {
                zone = z;
            }
        }
        let qname = if zone == "." {
            format!("{}.{}.", random_label(), random_label())
        } else {
            format!("{}.{}.{}", random_label(), random_label(), zone)
        };
        let st = Arc::new(State {
            zone,
            qname,
            seen: AtomicU32::new(0),
            off: AtomicBool::new(false),
            addr: Mutex::default(),
        });

        let host = c.config.listen_hosts.first().cloned().unwrap_or_default();
        let port = c.config.port.clone();
        let st2 = st.clone();
        c.on_startup(move || {
            let host = if host.is_empty() { "127.0.0.1".to_string() } else { host };
            let addr = if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                *st2.addr.lock().unwrap() = addr.clone();
                while tokio::time::Instant::now() < deadline {
                    if probe(&addr, &st2.qname).await.is_ok() {
                        break;
                    }
                    st2.seen.store(0, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                st2.off.store(true, Ordering::Relaxed);
            });
            Ok(())
        });
        c.add_plugin(move |next| Arc::new(Loop { next, st: st.clone() }));
        Ok(())
    }
}

async fn probe(addr: &str, qname: &str) -> std::io::Result<()> {
    let mut m = Message::new(rand_id(), MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    let name = Name::from_ascii(qname).map_err(std::io::Error::other)?;
    m.add_query(Query::query(name, RecordType::HINFO));
    let wire = m.to_vec().map_err(std::io::Error::other)?;
    let bind = if addr.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(&wire).await?;
    let mut buf = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    Ok(())
}

pub struct Loop {
    next: Next,
    st: Arc<State>,
}

#[async_trait]
impl Handler for Loop {
    fn name(&self) -> &'static str {
        "loop"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let st = &self.st;
        if req.qtype() != RecordType::HINFO || st.off.load(Ordering::Relaxed) {
            return next_or_failure("loop", &self.next, ctx, w, req).await;
        }
        let name = req.name();
        if !is_subdomain(&st.zone, &name) {
            return next_or_failure("loop", &self.next, ctx, w, req).await;
        }
        if name == st.qname {
            st.seen.fetch_add(1, Ordering::Relaxed);
        }
        if st.seen.load(Ordering::Relaxed) > 2 {
            kerndns_core::log::emit(
                "FATAL",
                Some("loop"),
                format_args!(
                    "Loop ({} -> {}) detected for zone {:?}, see https://coredns.io/plugins/loop#troubleshooting. Query: \"HINFO {}\"",
                    req.remote,
                    st.addr.lock().unwrap(),
                    st.zone,
                    st.qname
                ),
            );
            std::process::exit(1);
        }
        next_or_failure("loop", &self.next, ctx, w, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    #[test]
    fn setup() {
        assert!(setup_ok(&Setup, "loop"));
        assert!(setup_err(&Setup, "loop x").contains("Wrong argument count"));
        assert!(setup_err(&Setup, "loop\nloop").contains("only be used once"));
    }
}
