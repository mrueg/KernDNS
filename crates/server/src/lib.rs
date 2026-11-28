//! The KernDNS server: loads a Corefile into plugin chains and serves them
//! over UDP, TCP, DoT, DoH, DoH3, DoQ and gRPC.

pub mod config;
pub mod dispatch;
pub mod doh;
pub mod doh3;
pub mod grpc;
pub mod proxyproto;
pub mod quic;
pub mod tcp;
pub mod udp;
pub mod unpack;

use std::net::SocketAddr;
use std::sync::Arc;

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
    /// The UDP socket (plain DNS, DoQ, DoH3), if any.
    pub udp: Option<SocketAddr>,
    /// The TCP socket (plain DNS, DoT, DoH, gRPC), if any.
    pub tcp: Option<SocketAddr>,
    /// Servers on this address (`multisocket`, 1 without it).
    pub servers: usize,
}

impl ListenerInfo {
    /// The listener's port.
    pub fn port(&self) -> u16 {
        self.tcp.or(self.udp).map_or(0, |a| a.port())
    }
}

type ShutdownHook = Box<dyn FnOnce() + Send>;

struct Running {
    info: ListenerInfo,
    handle: DispatcherHandle,
    /// Our UDP, TCP, DoT, DoH, DoH3, DoQ and gRPC loops.
    tasks: tokio::task::JoinSet<()>,
    /// Socket settings fixed when the listener started: whether its UDP
    /// writes are decorated (`shed`) and its PROXY protocol settings.
    shed: bool,
    proxy: Option<Arc<kerndns_core::proxyproto::ProxyProtoConfig>>,
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
    /// Hooks for the final shutdown only (not run on reload).
    final_hooks: Vec<(&'static str, ShutdownHook)>,
    /// Event hooks of the running configuration (`on`).
    event_hooks: Vec<(String, kerndns_core::EventHook)>,
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

    /// Bind every listener of `plan`, run the startup hooks, then serve.
    /// Queries that arrive before the hooks are done wait for them, as
    /// CoreDNS starts its servers only after the `OnStartup` hooks.
    pub async fn start_plan(plan: Plan) -> Result<Self, StartError> {
        check_transports(&plan)?;
        let mut running = Vec::new();
        for l in &plan.listeners {
            match start_listener(l, true).await {
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
            final_hooks: plan.hooks.final_shutdown,
            event_hooks: plan.hooks.events,
        };
        inst.shutdown_hooks = plan.hooks.shutdown;
        for (name, hook) in plan.hooks.startup {
            if let Err(e) = hook() {
                inst.stop().await;
                return Err(StartError::Other(format!("plugin/{name}: {e}")));
            }
        }
        for r in &inst.running {
            r.handle.open();
        }
        inst.emit(kerndns_core::Event::Startup).await;
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
            match start_listener(l, false).await {
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
                    // QUIC listeners have one socket whatever `multisocket` says
                    let quic = matches!(l.transport, Transport::Quic | Transport::Https3);
                    if !quic && l.num_sockets.max(1) != r.info.servers {
                        kerndns_core::warning!(
                            "{}: multisocket changes from {} to {} after a restart, not on reload",
                            r.info.label,
                            r.info.servers,
                            l.num_sockets.max(1)
                        );
                    }
                    if l.udp_decorator.is_some() != r.shed {
                        kerndns_core::warning!(
                            "{}: adding or removing shed takes effect after a restart, not on reload",
                            r.info.label
                        );
                    }
                    if l.proxy_proto != r.proxy {
                        kerndns_core::warning!(
                            "{}: proxyproto changes take effect after a restart, not on reload",
                            r.info.label
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
        // the old configuration's final-shutdown hooks never run
        self.final_hooks = plan.hooks.final_shutdown;
        for (name, hook) in plan.hooks.startup {
            if let Err(e) = hook() {
                kerndns_core::error!("plugin/{name}: {e}");
            }
        }
        self.event_hooks = plan.hooks.events;
        self.emit(kerndns_core::Event::Startup).await;
        Ok(())
    }

    /// Run the event hooks for `event`, like caddy's `EmitEvent`: one
    /// after the other, errors logged. They may block (`on` runs
    /// commands), so they run on the blocking pool.
    pub async fn emit(&self, event: kerndns_core::Event) {
        for (name, hook) in &self.event_hooks {
            let (name, hook) = (name.clone(), hook.clone());
            let res = tokio::task::spawn_blocking(move || hook(event)).await;
            if let Ok(Err(e)) = res {
                println!("error on '{name}' hook: {e}");
            }
        }
    }

    pub fn listeners(&self) -> &[ListenerInfo] {
        &self.listeners
    }

    /// Run the shutdown hooks, then stop all listeners. Hooks run first so
    /// that e.g. `health`'s lameduck period keeps serving queries, as in
    /// CoreDNS. They may block, so they run on the blocking pool.
    pub async fn stop(&mut self) {
        for (_, hook) in self.final_hooks.drain(..).chain(self.shutdown_hooks.drain(..)) {
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
            // gRPC serves cleartext HTTP/2 without TLS, like CoreDNS
            Transport::Grpc => {}
            Transport::Https3 => {
                if l.tls.is_none() {
                    return Err(StartError::Other(format!(
                        "{}: DoH3 requires TLS, no TLS config found",
                        l.label()
                    )));
                }
            }
            Transport::Tls | Transport::Https | Transport::Quic => {
                if l.tls.is_none() {
                    return Err(StartError::Other(format!(
                        "{}: no TLS configuration (use the tls plugin)",
                        l.label()
                    )));
                }
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

/// `held`: requests wait until the handle is opened (first start: the
/// startup hooks run between binding and serving).
async fn start_listener(l: &config::ListenerPlan, held: bool) -> Result<Running, StartError> {
    // `multisocket` (num_sockets > 0) gives that many UDP sockets and TCP
    // listeners, each a server of its own; without it one TCP listener and
    // one UDP socket per CPU. QUIC listeners use one UDP socket.
    let n = l.num_sockets;
    let (udp_count, tcp_count) = match l.transport {
        Transport::Dns => (if n > 0 { n } else { udp_sockets() }, n.max(1)),
        Transport::Tls | Transport::Https | Transport::Grpc => (0, n.max(1)),
        Transport::Quic | Transport::Https3 => (1, 0),
    };
    let (udp, tcp) = bind(&l.host, &l.port, udp_count, tcp_count).await?;
    let local_err = |e: std::io::Error| StartError::Other(e.to_string());
    let tcp_local = tcp.first().map(|t| t.local_addr()).transpose().map_err(local_err)?;
    let udp_local = udp.first().map(|u| u.local_addr()).transpose().map_err(local_err)?;
    let any_local = tcp_local.or(udp_local).expect("bound at least one socket");
    let label = l.label();
    let dispatcher = Dispatcher::new(
        label.clone(),
        &l.zones,
        l.class_chaos,
        udp_local.unwrap_or(any_local),
        tcp_local.unwrap_or(any_local),
    );
    if held {
        dispatcher.hold();
    }
    let handle = dispatcher.handle();
    let conn = tcp::Limits::from(&l.conn);
    let tls = |alpn: &[&[u8]]| {
        let mut cfg = (**l.tls.as_ref().expect("checked")).clone();
        cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(cfg))
    };
    let quic_socket = |udp: Vec<UdpSocket>| {
        udp.into_iter()
            .next()
            .expect("one socket")
            .into_std()
            .map_err(|e| StartError::Other(e.to_string()))
    };
    let servers = tcp.len().max(1);
    let mut tasks = match l.transport {
        Transport::Dns => udp::serve(
            udp,
            dispatcher.clone(),
            any_local,
            l.udp_decorator.clone(),
            l.proxy_proto.clone().map(|p| Arc::new(proxyproto::UdpProxy::new(p))),
        ),
        Transport::Quic => {
            let s = quic::Settings::new(&l.limits, &conn);
            let ep = quic::endpoint(
                quic_socket(udp)?,
                l.tls.as_ref().expect("checked"),
                &[b"doq"],
                Some(s.max_streams),
                s.idle_timeout,
            )
            .map_err(|e| StartError::Other(format!("{label}: {e}")))?;
            quic::serve(ep, dispatcher.clone(), any_local, s)
        }
        Transport::Https3 => {
            let s = doh3::Settings::new(&l.limits, &conn);
            let ep = doh3::endpoint(quic_socket(udp)?, l.tls.as_ref().expect("checked"), &s)
                .map_err(|e| StartError::Other(format!("{label}: {e}")))?;
            doh3::serve(ep, dispatcher.clone(), any_local, s)
        }
        Transport::Tls | Transport::Https | Transport::Grpc => tokio::task::JoinSet::new(),
    };
    for t in tcp {
        let d = dispatcher.clone();
        let set = match l.transport {
            Transport::Dns => tcp::serve(t, d, any_local, None, conn, l.proxy_proto.clone()),
            Transport::Tls => tcp::serve(t, d, any_local, Some(tls(&[b"dot"])), conn, l.proxy_proto.clone()),
            Transport::Https => doh::serve(
                t,
                d,
                any_local,
                tls(&[b"h2", b"http/1.1"]),
                doh::Settings::new(&l.limits),
                l.proxy_proto.clone(),
            ),
            Transport::Grpc => {
                let acc = l.tls.as_ref().map(|_| tls(&[b"h2"]));
                grpc::serve(
                    t,
                    d,
                    any_local,
                    acc,
                    grpc::Settings::new(&l.limits),
                    l.proxy_proto.clone(),
                )
            }
            Transport::Quic | Transport::Https3 => unreachable!("no TCP listener"),
        };
        tasks = merge(tasks, set);
    }
    let info = ListenerInfo {
        label,
        zones: l.zones.iter().map(|(z, _)| z.clone()).collect(),
        udp: udp_local,
        tcp: tcp_local,
        servers,
    };
    Ok(Running {
        info,
        handle,
        tasks,
        shed: l.udp_decorator.is_some(),
        proxy: l.proxy_proto.clone(),
    })
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

/// Bind `udp_count` UDP sockets and `tcp_count` TCP listeners on
/// `host:port`, all with `SO_REUSEPORT`. An empty host means all
/// interfaces: `[::]` (dual stack), falling back to `0.0.0.0` without IPv6.
/// Parse a listen address, `[fe80::1%eth0]:53` included: `bind` gives
/// IPv6 link-local addresses of an interface with the interface as zone,
/// which becomes the socket's scope id.
fn socket_addr(addr: &str) -> Result<std::net::SocketAddr, String> {
    if let Some((host, port)) = addr.strip_prefix('[').and_then(|a| a.rsplit_once("]:"))
        && let Some((ip, zone)) = host.split_once('%')
    {
        let ip: std::net::Ipv6Addr = ip.parse().map_err(|e| format!("{e}"))?;
        let port: u16 = port.parse().map_err(|e| format!("invalid port {port:?}: {e}"))?;
        let scope = match zone.parse::<u32>() {
            Ok(n) => n,
            Err(_) => if_addrs::get_if_addrs()
                .map_err(|e| e.to_string())?
                .into_iter()
                .find(|i| i.name == zone)
                .and_then(|i| i.index)
                .ok_or_else(|| format!("unknown interface {zone:?}"))?,
        };
        return Ok(std::net::SocketAddrV6::new(ip, port, 0, scope).into());
    }
    addr.parse().map_err(|e| format!("{e}"))
}

async fn bind(
    host: &str,
    port: &str,
    udp_count: usize,
    tcp_count: usize,
) -> Result<(Vec<UdpSocket>, Vec<TcpListener>), StartError> {
    let candidates: Vec<String> = if host.is_empty() {
        vec![format!("[::]:{port}"), format!("0.0.0.0:{port}")]
    } else if host.contains(':') {
        vec![format!("[{host}]:{port}")]
    } else {
        vec![format!("{host}:{port}")]
    };
    let mut last_err = None;
    for addr in &candidates {
        let sa = match socket_addr(addr) {
            Ok(a) => a,
            Err(e) => {
                last_err = Some((addr.clone(), std::io::Error::new(std::io::ErrorKind::InvalidInput, e)));
                continue;
            }
        };
        let udp = match if udp_count > 0 {
            udp::bind_reuseport(sa, udp_count)
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
        if tcp_count == 0 {
            return Ok((udp, Vec::new()));
        }
        match tcp::bind_reuseport(sa, tcp_count).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(e) => last_err = Some((addr.clone(), e)),
        }
    }
    let (addr, source) = last_err.expect("at least one candidate");
    Err(StartError::Bind { addr, source })
}

#[cfg(test)]
mod tests {
    use super::socket_addr;

    #[test]
    fn listen_address_with_zone() {
        assert_eq!(socket_addr("127.0.0.1:53").unwrap().to_string(), "127.0.0.1:53");
        assert_eq!(socket_addr("[::1]:53").unwrap().to_string(), "[::1]:53");
        let std::net::SocketAddr::V6(v6) = socket_addr("[fe80::1%7]:1053").unwrap() else {
            panic!("not IPv6")
        };
        assert_eq!((v6.scope_id(), v6.port()), (7, 1053));
        if let Some(lo) = if_addrs::get_if_addrs().unwrap().into_iter().find(|i| i.name == "lo") {
            let std::net::SocketAddr::V6(v6) = socket_addr("[fe80::1%lo]:53").unwrap() else {
                panic!("not IPv6")
            };
            assert_eq!(Some(v6.scope_id()), lo.index);
        }
        assert!(
            socket_addr("[fe80::1%nosuchif0]:53")
                .unwrap_err()
                .contains("unknown interface")
        );
    }
}
