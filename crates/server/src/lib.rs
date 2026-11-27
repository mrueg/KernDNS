//! The KernDNS server: loads a Corefile into plugin chains and serves them on
//! hickory-server listeners.

pub mod config;
pub mod dispatch;
pub mod doh;
pub mod tcp;
pub mod udp;

use std::net::SocketAddr;

use kerndns_core::{Registry, Transport};
use tokio::net::{TcpListener, UdpSocket};

pub use config::{LoadError, Options, Plan, load};
pub use dispatch::{Dispatcher, DispatcherHandle};

/// Addresses a listener is bound to.
#[derive(Debug, Clone)]
pub struct ListenerInfo {
    /// e.g. `dns://:53`.
    pub label: String,
    pub zones: Vec<String>,
    pub udp: SocketAddr,
    pub tcp: SocketAddr,
    /// Servers on this address (`multisocket`, 1 without it).
    pub servers: usize,
}

type ShutdownHook = Box<dyn FnOnce() + Send>;

struct Running {
    info: ListenerInfo,
    handle: DispatcherHandle,
    /// Our UDP, TCP, DoT and DoH loops.
    tasks: tokio::task::JoinSet<()>,
}

impl Running {
    async fn shutdown(&mut self) {
        self.tasks.abort_all();
    }
}

/// A running server: every listener of one Corefile.
pub struct Instance {
    running: Vec<Running>,
    listeners: Vec<ListenerInfo>,
    shutdown_hooks: Vec<(&'static str, ShutdownHook)>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Load(#[from] LoadError),
    #[error("listen {addr}: {source}")]
    Bind { addr: String, source: std::io::Error },
    #[error("{0}")]
    Other(String),
}

impl Instance {
    /// Load `corefile` and start serving it.
    pub async fn start(corefile: &str, path: &str, registry: &Registry, opts: &Options) -> Result<Self, StartError> {
        let plan = load(corefile, path, registry, opts)?;
        Self::start_plan(plan).await
    }

    /// Bind every listener of `plan`, then run the startup hooks.
    pub async fn start_plan(plan: Plan) -> Result<Self, StartError> {
        check_transports(&plan)?;
        let mut running = Vec::new();
        for l in &plan.listeners {
            match start_listener(l).await {
                Ok(r) => running.push(r),
                Err(e) => {
                    for mut r in running {
                        r.shutdown().await;
                    }
                    return Err(e);
                }
            }
        }
        let mut inst = Instance {
            listeners: running.iter().map(|r| r.info.clone()).collect(),
            running,
            shutdown_hooks: Vec::new(),
        };
        inst.shutdown_hooks = plan.hooks.shutdown;
        for (name, hook) in plan.hooks.startup {
            if let Err(e) = hook() {
                inst.stop().await;
                return Err(StartError::Other(format!("plugin/{name}: {e}")));
            }
        }
        Ok(inst)
    }

    /// Switch to a new configuration. Listeners with the same address keep
    /// their sockets and get the new plugin chains; new ones are bound,
    /// removed ones closed. If binding fails, the old configuration stays.
    pub async fn reload(&mut self, plan: Plan) -> Result<(), StartError> {
        check_transports(&plan)?;
        // bind what's new first, so a failure leaves everything as it was
        let mut fresh: Vec<Running> = Vec::new();
        for l in &plan.listeners {
            if self.running.iter().any(|r| r.info.label == l.label()) {
                continue;
            }
            match start_listener(l).await {
                Ok(r) => fresh.push(r),
                Err(e) => {
                    for mut r in fresh {
                        r.shutdown().await;
                    }
                    return Err(e);
                }
            }
        }

        for (_, hook) in self.shutdown_hooks.drain(..) {
            let _ = tokio::task::spawn_blocking(hook).await;
        }

        let mut next: Vec<Running> = Vec::new();
        let old = std::mem::take(&mut self.running);
        let mut keep: Vec<Running> = Vec::new();
        for mut r in old {
            match plan.listeners.iter().find(|l| l.label() == r.info.label) {
                Some(l) => {
                    if l.num_sockets.max(1) != r.info.servers {
                        kerndns_core::warning!(
                            "{}: multisocket changes from {} to {} after a restart, not on reload",
                            r.info.label,
                            r.info.servers,
                            l.num_sockets.max(1)
                        );
                    }
                    r.handle.update(&l.zones, l.class_chaos);
                    r.info.zones = l.zones.iter().map(|(z, _)| z.clone()).collect();
                    keep.push(r);
                }
                None => {
                    r.shutdown().await;
                }
            }
        }
        // keep Corefile order
        for l in &plan.listeners {
            let label = l.label();
            if let Some(i) = keep.iter().position(|r| r.info.label == label) {
                next.push(keep.swap_remove(i));
            } else if let Some(i) = fresh.iter().position(|r| r.info.label == label) {
                next.push(fresh.swap_remove(i));
            }
        }
        self.running = next;
        self.listeners = self.running.iter().map(|r| r.info.clone()).collect();
        self.shutdown_hooks = plan.hooks.shutdown;
        for (name, hook) in plan.hooks.startup {
            if let Err(e) = hook() {
                kerndns_core::error!("plugin/{name}: {e}");
            }
        }
        Ok(())
    }

    pub fn listeners(&self) -> &[ListenerInfo] {
        &self.listeners
    }

    /// Run the shutdown hooks, then stop all listeners. Hooks run first so
    /// that e.g. `health`'s lameduck period keeps serving queries, as in
    /// CoreDNS. They may block, so they run on the blocking pool.
    pub async fn stop(&mut self) {
        for (_, hook) in self.shutdown_hooks.drain(..) {
            let _ = tokio::task::spawn_blocking(hook).await;
        }
        for r in &mut self.running {
            r.shutdown().await;
        }
        self.running.clear();
    }
}

fn check_transports(plan: &Plan) -> Result<(), StartError> {
    for l in &plan.listeners {
        match l.transport {
            Transport::Dns => {}
            Transport::Tls | Transport::Https => {
                if l.tls.is_none() {
                    return Err(StartError::Other(format!(
                        "{}: no TLS configuration (use the tls plugin)",
                        l.label()
                    )));
                }
            }
            t => {
                return Err(StartError::Other(format!(
                    "{}: the {t}:// transport is not supported by KernDNS yet",
                    l.label()
                )));
            }
        }
    }
    Ok(())
}

/// UDP sockets per listener: one per available CPU, at most 16.
fn udp_sockets() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(16)
}

async fn start_listener(l: &config::ListenerPlan) -> Result<Running, StartError> {
    let with_udp = l.transport == Transport::Dns;
    let (udp, tcp) = bind(&l.host, &l.port, with_udp, l.num_sockets).await?;
    let tcp_local = tcp[0].local_addr().map_err(|e| StartError::Other(e.to_string()))?;
    let udp_local = match udp.first() {
        Some(u) => u.local_addr().map_err(|e| StartError::Other(e.to_string()))?,
        None => tcp_local,
    };
    let label = l.label();
    let dispatcher = Dispatcher::new(label.clone(), &l.zones, l.class_chaos, udp_local, tcp_local);
    let handle = dispatcher.handle();
    let servers = tcp.len();
    let mut tasks = match l.transport {
        Transport::Dns => udp::serve(udp, dispatcher.clone(), udp_local),
        _ => tokio::task::JoinSet::new(),
    };
    for tcp in tcp {
        let d = dispatcher.clone();
        let t = match l.transport {
            Transport::Dns => tcp::serve(tcp, d, tcp_local, None, tcp::Limits::from(&l.conn)),
            Transport::Tls => {
                let mut cfg = (**l.tls.as_ref().expect("checked")).clone();
                cfg.alpn_protocols = vec![b"dot".to_vec()];
                let acc = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
                tcp::serve(tcp, d, tcp_local, Some(acc), tcp::Limits::from(&l.conn))
            }
            Transport::Https => {
                let mut cfg = (**l.tls.as_ref().expect("checked")).clone();
                cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                let acc = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg));
                doh::serve(tcp, d, tcp_local, acc, "/dns-query")
            }
            _ => unreachable!("checked by check_transports"),
        };
        tasks = merge(tasks, t);
    }
    let info = ListenerInfo {
        label,
        zones: l.zones.iter().map(|(z, _)| z.clone()).collect(),
        udp: udp_local,
        tcp: tcp_local,
        servers,
    };
    Ok(Running { info, handle, tasks })
}

fn merge(mut a: tokio::task::JoinSet<()>, b: tokio::task::JoinSet<()>) -> tokio::task::JoinSet<()> {
    // JoinSets can't be merged; keep b's tasks alive by awaiting them in a
    // task owned by a (aborting a aborts that task, which drops b).
    a.spawn(async move {
        let mut b = b;
        while b.join_next().await.is_some() {}
    });
    a
}

/// Bind UDP (several `SO_REUSEPORT` sockets) and TCP on `host:port`. An
/// empty host means all interfaces: `[::]` (dual stack), falling back to
/// `0.0.0.0` without IPv6. With `multisocket` (`num_sockets` > 0) there are
/// that many UDP sockets and TCP listeners; without it one TCP listener and
/// one UDP socket per CPU.
async fn bind(
    host: &str,
    port: &str,
    with_udp: bool,
    num_sockets: usize,
) -> Result<(Vec<UdpSocket>, Vec<TcpListener>), StartError> {
    let udp_n = if num_sockets > 0 { num_sockets } else { udp_sockets() };
    let candidates: Vec<String> = if host.is_empty() {
        vec![format!("[::]:{port}"), format!("0.0.0.0:{port}")]
    } else if host.contains(':') {
        vec![format!("[{host}]:{port}")]
    } else {
        vec![format!("{host}:{port}")]
    };
    let mut last_err = None;
    for addr in &candidates {
        let sa: std::net::SocketAddr = match addr.parse() {
            Ok(a) => a,
            Err(e) => {
                last_err = Some((addr.clone(), std::io::Error::new(std::io::ErrorKind::InvalidInput, e)));
                continue;
            }
        };
        let udp = match if with_udp {
            udp::bind_reuseport(sa, udp_n)
        } else {
            Ok(Vec::new())
        } {
            Ok(s) => s,
            // the port is taken: don't retry on 0.0.0.0, report it
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                return Err(StartError::Bind {
                    addr: addr.clone(),
                    source: e,
                });
            }
            Err(e) => {
                last_err = Some((addr.clone(), e));
                continue;
            }
        };
        match tcp::bind_reuseport(sa, num_sockets.max(1)).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(e) => last_err = Some((addr.clone(), e)),
        }
    }
    let (addr, source) = last_err.expect("at least one candidate");
    Err(StartError::Bind { addr, source })
}
