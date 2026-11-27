//! Per-listener request routing, a port of `dnsserver.Server.ServeDNS`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;
use futures_util::FutureExt;
use kerndns_core::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{DNSClass, Name, RecordType};
use kerndns_core::wire::{to_wire, truncate_oversized};
pub use kerndns_core::wire::{truncate, wire_len};
use kerndns_core::{
    CaptureWriter, Context, Handler, PluginError, Protocol, Request, ResponseSigner, Upstream, client_write,
    result_rcode,
};

use crate::config::ZoneHandler;

/// What to send for one request.
pub struct Answer {
    pub msgs: Vec<Message>,
    /// Signs each encoded message (TSIG), if a plugin asked for it.
    pub signer: Option<Arc<dyn ResponseSigner>>,
    /// Told the encoded size once the answer is on the wire.
    pub on_sent: Vec<kerndns_core::handler::SentHook>,
    /// A smaller EDNS UDP size a plugin applied to the request (`bufsize`).
    pub bufsize: Option<u16>,
    /// The request's OPT record as a plugin rewrote it (`rewrite edns0`).
    pub edns: Option<Box<Edns>>,
}

impl From<Vec<Message>> for Answer {
    fn from(msgs: Vec<Message>) -> Self {
        Answer {
            msgs,
            signer: None,
            on_sent: Vec::new(),
            bufsize: None,
            edns: None,
        }
    }
}

/// `req` as the plugins left it: with a rewritten OPT record (`edns`) and
/// the EDNS size `bufsize` applied.
pub fn effective_request<'a>(
    req: &'a Request,
    edns: Option<&Edns>,
    bufsize: Option<u16>,
) -> std::borrow::Cow<'a, Request> {
    let mut r = std::borrow::Cow::Borrowed(req);
    if let Some(e) = edns {
        r.to_mut().msg.edns = Some(e.clone());
    }
    if let Some(b) = bufsize
        && r.edns().is_some_and(|e| e.max_payload() > b)
        && let Some(e) = r.to_mut().msg.edns.as_mut()
    {
        e.set_max_payload(b);
    }
    r
}

impl Answer {
    /// The messages, for callers that don't encode them; the hooks get the
    /// size they would have on the wire.
    fn into_msgs(self, req: &Request) -> Vec<Message> {
        let mut msgs = self.msgs;
        scrub_truncate(&effective_request(req, self.edns.as_deref(), self.bufsize), &mut msgs);
        if !self.on_sent.is_empty() {
            let n = msgs.iter().map(|m| to_wire(m).map_or(0, |v| v.len())).sum();
            for h in &self.on_sent {
                h(n);
            }
        }
        msgs
    }
}

/// Encode an answer for the wire: each response is truncated to `size`
/// if needed, then signed.
pub fn encode(answer: Answer, size: usize) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for mut m in answer.msgs {
        if m.metadata.message_type != MessageType::Response {
            continue;
        }
        let Ok(mut wire) = to_wire(&m) else { continue };
        let size = size.max(512);
        if wire.len() > size {
            truncate_oversized(&mut m, size);
            match to_wire(&m) {
                Ok(w) => wire = w,
                Err(_) => continue,
            }
        }
        if let Some(s) = &answer.signer {
            wire = s.sign(wire);
        }
        out.push(wire);
    }
    if !answer.on_sent.is_empty() {
        let n = out.iter().map(Vec::len).sum();
        for h in &answer.on_sent {
            h(n);
        }
    }
    out
}

/// Routes requests on one listener to the zone's plugin chain.
#[derive(Clone)]
pub struct Dispatcher(Arc<Inner>);

/// The part of a listener that a reload replaces.
struct Routes {
    zones: HashMap<String, Vec<Arc<ZoneHandler>>>,
    class_chaos: bool,
}

fn routes(zones: &[(String, Arc<ZoneHandler>)], class_chaos: bool) -> Routes {
    let mut map: HashMap<String, Vec<Arc<ZoneHandler>>> = HashMap::new();
    for (z, h) in zones {
        map.entry(z.clone()).or_default().push(h.clone());
    }
    Routes {
        zones: map,
        class_chaos,
    }
}

struct Inner {
    label: Arc<str>,
    routes: ArcSwap<Routes>,
    udp_local: SocketAddr,
    tcp_local: SocketAddr,
    /// Handed to plugins in `Context::upstream`; holds a weak reference back.
    upstream: Arc<dyn Upstream>,
}

/// Re-enters the dispatcher for internal lookups, like CoreDNS's
/// `upstream.Lookup` calling `Server.ServeDNS` with a non-writing writer.
struct SelfUpstream(Weak<Inner>);

#[kerndns_core::async_trait]
impl Upstream for SelfUpstream {
    async fn lookup(
        &self,
        ctx: &Context,
        req: &Request,
        name: &Name,
        qtype: RecordType,
    ) -> Result<Option<Message>, PluginError> {
        let Some(inner) = self.0.upgrade() else {
            return Err(PluginError::servfail("upstream", "server is shutting down"));
        };
        // NewWithQuestion: same request, new question (class IN)
        let mut r = req.clone();
        let mut name = name.clone();
        name.set_fqdn(true);
        r.msg.queries = vec![Query::query(name, qtype)];
        let msgs = inner.serve(&r, Some(ctx)).await.into_msgs(&r);
        Ok(msgs.into_iter().last())
    }
}

impl Dispatcher {
    pub fn new(
        label: String,
        zones: &[(String, Arc<ZoneHandler>)],
        class_chaos: bool,
        udp_local: SocketAddr,
        tcp_local: SocketAddr,
    ) -> Self {
        Dispatcher(Arc::new_cyclic(|weak| Inner {
            label: Arc::from(label),
            routes: ArcSwap::from_pointee(routes(zones, class_chaos)),
            udp_local,
            tcp_local,
            upstream: Arc::new(SelfUpstream(weak.clone())),
        }))
    }

    /// Serve one request and return the messages to send.
    pub async fn serve(&self, req: &Request) -> Vec<Message> {
        self.0.serve(req, None).await.into_msgs(req)
    }

    /// Serve one request; the answer may come with a signer (TSIG).
    pub async fn answer(&self, req: &Request) -> Answer {
        self.0.serve(req, None).await
    }

    /// The listener's label, e.g. `dns://:53` (the `server` metrics label).
    pub fn label(&self) -> &str {
        &self.0.label
    }

    /// A handle that can swap in a new routing table later (reload).
    pub fn handle(&self) -> DispatcherHandle {
        DispatcherHandle(self.0.clone())
    }
}

/// Lets a reload replace a running listener's zones and plugin chains.
#[derive(Clone)]
pub struct DispatcherHandle(Arc<Inner>);

impl DispatcherHandle {
    pub fn update(&self, zones: &[(String, Arc<ZoneHandler>)], class_chaos: bool) {
        self.0.routes.store(Arc::new(routes(zones, class_chaos)));
    }
}

impl Inner {
    /// Serve one request and return the messages to send. `parent` is the
    /// context that made an internal lookup through `upstream`: its loop
    /// count and synthesis flag carry over.
    async fn serve(&self, req: &Request, parent: Option<&Context>) -> Answer {
        let start = std::time::Instant::now();
        let op = req.msg.metadata.op_code;
        let update = op == OpCode::Update;
        if op != OpCode::Query && op != OpCode::Notify {
            // miekg/dns's accept func: NOTIMP unless a plugin on this
            // listener opted in, and then exactly one question
            let routes = self.routes.load();
            if !update || !routes.zones.values().flatten().any(|h| h.allow_update) {
                return vec![error_reply(req, ResponseCode::NotImp)].into();
            }
            if req.msg.queries.len() != 1 {
                return vec![error_reply(req, ResponseCode::FormErr)].into();
            }
        }
        if req.msg.queries.is_empty() {
            return vec![self.dropped(req, ResponseCode::ServFail, start)].into();
        }
        let routes = self.routes.load_full();
        if !routes.class_chaos && req.qclass() != DNSClass::IN {
            return vec![self.dropped(req, ResponseCode::Refused, start)].into();
        }
        if let Some(edns) = req.edns()
            && edns.version() > 0
        {
            return vec![badvers(req)].into();
        }

        let qname = req.name();
        let is_ds = req.qtype() == RecordType::DS;
        let mut ds_handler: Option<(&Arc<ZoneHandler>, Context)> = None;

        // Longest match first: try "a.b.c.", then "b.c.", then "c.". Blocks
        // for the same zone are tried in order until one's filters (`view`)
        // accept the request.
        let mut off = 0;
        loop {
            if let Some(handlers) = routes.zones.get(&qname[off..]) {
                for h in handlers {
                    if h.chain.is_none() {
                        return vec![self.dropped(req, ResponseCode::Refused, start)].into();
                    }
                    let Some(ctx) = self.accept(h, req, parent) else {
                        continue;
                    };
                    if update && !h.allow_update {
                        return vec![self.dropped(req, ResponseCode::NotImp, start)].into();
                    }
                    if !is_ds {
                        return self.run(h, req, ctx).await;
                    }
                    // DS belongs to the parent: remember and keep looking up.
                    ds_handler = Some((h, ctx));
                }
            }
            match next_label(&qname, off) {
                Some(n) => off = n,
                None => break,
            }
        }
        if let Some((h, ctx)) = ds_handler {
            return self.run(h, req, ctx).await;
        }
        for h in routes.zones.get(".").into_iter().flatten() {
            if h.chain.is_none() {
                continue;
            }
            let Some(ctx) = self.accept(h, req, parent) else {
                continue;
            };
            if update && !h.allow_update {
                return vec![self.dropped(req, ResponseCode::NotImp, start)].into();
            }
            return self.run(h, req, ctx).await;
        }
        vec![self.dropped(req, ResponseCode::Refused, start)].into()
    }

    /// The request context for `h` if the block takes the request: its
    /// metadata is collected first, then its filters run, like CoreDNS.
    fn accept(&self, h: &ZoneHandler, req: &Request, parent: Option<&Context>) -> Option<Context> {
        let mut ctx = Context::new(h.zone.clone(), self.label.clone());
        ctx.upstream = Some(self.upstream.clone());
        if let Some(p) = parent {
            ctx.loop_count = p.loop_count;
            ctx.synthesis = p.synthesis;
        }
        if let Some(m) = &h.metadata {
            m.collect(&mut ctx, req);
        }
        if !h.filters.iter().all(|f| f.filter(&ctx, req)) {
            return None;
        }
        ctx.view = h.view_name.clone();
        Some(ctx)
    }

    /// `errorAndMetricsFunc`: an error answer from the server itself,
    /// counted under the "dropped" zone.
    fn dropped(&self, req: &Request, rcode: ResponseCode, start: std::time::Instant) -> Message {
        let m = error_reply(req, rcode);
        let size = to_wire(&m).map(|v| v.len()).unwrap_or(0);
        kerndns_core::metrics::report(
            &self.label,
            req,
            kerndns_core::metrics::DROPPED,
            "",
            rcode,
            "",
            size,
            start,
        );
        m
    }

    async fn run(&self, zh: &ZoneHandler, req: &Request, mut ctx: Context) -> Answer {
        let chain: &Arc<dyn Handler> = zh.chain.as_ref().expect("checked by caller");
        let mut w = CaptureWriter::new();

        let fut = chain.serve_dns(&mut ctx, &mut w, req);
        let res = if zh.debug {
            Some(fut.await)
        } else {
            match AssertUnwindSafe(fut).catch_unwind().await {
                Ok(r) => Some(r),
                Err(panic) => {
                    let msg = panic
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "panic".into());
                    kerndns_core::error!("Recovered from panic in server: {:?} {}", self.label, msg);
                    kerndns_core::metrics::PANICS.inc();
                    None
                }
            }
        };

        let mut msgs = w.msgs;
        match res {
            None => {
                if msgs.is_empty() {
                    msgs.push(error_reply(req, ResponseCode::ServFail));
                }
            }
            Some(r) => {
                let rc = result_rcode(&r);
                if !client_write(rc) && msgs.is_empty() {
                    msgs.push(error_reply(req, rc));
                }
            }
        }
        let sreq = effective_request(req, ctx.edns.as_deref(), ctx.bufsize);
        for m in &mut msgs {
            scrub(&sreq, m);
        }
        Answer {
            msgs,
            signer: ctx.signer,
            on_sent: ctx.on_sent,
            bufsize: ctx.bufsize,
            edns: ctx.edns,
        }
    }

    #[allow(dead_code)]
    fn local_for(&self, protocol: Protocol) -> SocketAddr {
        if protocol == Protocol::Udp {
            self.udp_local
        } else {
            self.tcp_local
        }
    }
}

/// Offset of the next label in a presentation-format name, like
/// `dns.NextLabel`; `None` at the end.
fn next_label(name: &str, off: usize) -> Option<usize> {
    let bytes = name.as_bytes();
    let mut i = off;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'.' => {
                return if i + 1 < bytes.len() { Some(i + 1) } else { None };
            }
            _ => i += 1,
        }
    }
    None
}

/// `errorFunc`: a reply carrying only `rcode`, with EDNS echoed.
fn error_reply(req: &Request, rcode: ResponseCode) -> Message {
    let mut m = req.error_reply(rcode);
    scrub(req, &mut m);
    m
}

/// `edns.Version`: answer BADVERS to EDNS versions above 0.
fn badvers(req: &Request) -> Message {
    let mut m = req.reply();
    m.metadata.response_code = ResponseCode::BADVERS;
    let mut opt = Edns::new();
    opt.set_version(0);
    opt.set_max_payload(req.bufsize().max(512));
    m.edns = Some(opt);
    m
}

/// The EDNS half of `ScrubWriter`: echo the client's EDNS. Truncation to
/// what the client accepts happens once, while encoding ([`encode`]), so a
/// response that fits is serialized only once.
pub fn scrub(req: &Request, m: &mut Message) {
    req.size_and_do(m);
    if let Some(e) = m.edns.as_mut() {
        // the encoder uses the OPT payload as the UDP size limit
        e.set_max_payload(e.max_payload().max(512));
    }
}

/// `scrub` plus the truncation, for answers that are not encoded here.
fn scrub_truncate(req: &Request, msgs: &mut [Message]) {
    if req.proto() == "udp" {
        for m in msgs {
            truncate(m, req.size() as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerndns_core::proto::op::{OpCode, Query};
    use kerndns_core::proto::rr::rdata::TXT;
    use kerndns_core::proto::rr::{Name, RData, Record};

    #[test]
    fn labels() {
        let n = "a.b.c.";
        assert_eq!(next_label(n, 0), Some(2));
        assert_eq!(next_label(n, 2), Some(4));
        assert_eq!(next_label(n, 4), None);
        assert_eq!(next_label(".", 0), None);
        assert_eq!(next_label("a\\.b.c.", 0), Some(5));
    }

    #[test]
    #[allow(deprecated)] // TXT::new is the simplest constructor for a test
    fn truncates() {
        let mut m = Message::new(1, MessageType::Response, OpCode::Query);
        let name = Name::from_ascii("example.org.").unwrap();
        m.add_query(Query::query(name.clone(), RecordType::TXT));
        for i in 0..20 {
            m.add_answer(Record::from_rdata(
                name.clone(),
                0,
                RData::TXT(TXT::new(vec![format!("{i:0>60}")])),
            ));
        }
        assert!(wire_len(&m) > 512);
        truncate(&mut m, 512);
        assert!(m.metadata.truncation);
        assert!(wire_len(&m) <= 512);
        assert!(!m.answers.is_empty());
    }
}
