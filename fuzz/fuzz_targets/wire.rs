//! Arbitrary packets through the server's request path (`udp::handle`:
//! parse, route, plugin chain, truncate, encode) for a representative
//! chain (`fixtures/Corefile.wire`: acl, header, rewrite, cache,
//! loadbalance, template, file; tsig, minimal, bufsize, nsid, any, hosts,
//! dns64; chaos, local, whoami). The first byte picks the transport and
//! whether the packet goes through `unpack_request` first, as DoH, DoH3,
//! DoQ and gRPC do. It must never panic.
#![no_main]

use std::net::SocketAddr;
use std::sync::OnceLock;

use kerndns_core::Protocol;
use kerndns_fuzz::{fixtures, registry, runtime};
use kerndns_server::config::{Options, load};
use kerndns_server::dispatch::Dispatcher;
use kerndns_server::udp::{answer, handle};
use kerndns_server::unpack::unpack_request;
use libfuzzer_sys::fuzz_target;

fn dispatcher() -> &'static Dispatcher {
    static D: OnceLock<Dispatcher> = OnceLock::new();
    D.get_or_init(|| {
        let dir = fixtures();
        let corefile = std::fs::read_to_string(dir.join("Corefile.wire"))
            .expect("Corefile.wire")
            .replace("{FIX}", &dir.display().to_string());
        let path = dir.join("Corefile").display().to_string();
        let _guard = runtime().enter();
        let plan = load(&corefile, &path, registry(), &Options { dns_port: "53".into() }).expect("Corefile.wire loads");
        for (name, hook) in plan.hooks.startup {
            hook().unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        let l = &plan.listeners[0];
        let local: SocketAddr = "127.0.0.1:53".parse().unwrap();
        Dispatcher::new("dns://:53".into(), &l.zones, l.class_chaos, local, local)
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, packet)) = data.split_first() else {
        return;
    };
    let d = dispatcher();
    let local: SocketAddr = "127.0.0.1:53".parse().unwrap();
    let src: SocketAddr = if mode & 4 == 0 {
        "127.0.0.1:40000".parse().unwrap()
    } else {
        "[2001:db8::7]:40000".parse().unwrap()
    };
    let proto = if mode & 1 == 0 { Protocol::Udp } else { Protocol::Tcp };
    runtime().block_on(async {
        if mode & 2 == 0 {
            let _ = handle(d, packet, src, local, proto, Default::default()).await;
        } else if let Ok(msg) = unpack_request(packet) {
            let _ = answer(d, msg, packet, src, local, Protocol::Https, Default::default()).await;
        }
    });
});
