//! `dnstap`: logs client queries and responses as dnstap messages over
//! Frame Streams. Port of `plugin/dnstap`.
//!
//! ```text
//! dnstap SOCKET [full] [WRITEBUFFER] [QUEUE] {
//!     identity IDENTITY
//!     version VERSION
//!     extra EXTRA
//!     skipverify
//! }
//! dnstap listen SOCKET [full] {
//!     identity IDENTITY
//!     version VERSION
//!     extra EXTRA
//!     tls CERT KEY [CA]
//!     skipverify
//! }
//! ```
//!
//! SOCKET is a unix socket path (optionally `unix://`), `tcp://HOST:PORT`
//! or `tls://HOST:PORT`. Other plugins log through the block's [`Taps`]
//! (CoreDNS's `dnstap.Dnstap` interface): `forward` sends
//! FORWARDER_QUERY / FORWARDER_RESPONSE messages there.
//!
//! The protobuf messages and the Frame Streams protocol are written by
//! hand ([`msg`], [`framestream`]), like the gRPC listener's `DnsPacket`.

pub mod framestream;
pub mod io;
pub mod listener;
pub mod msg;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use bytes::Bytes;
use kerndns_core::plugin::Metadata;
use kerndns_core::proto::op::Message as DnsMessage;
use kerndns_core::{
    BlockConfig, Context, Controller, Handler, HandlerResult, Next, PluginFactory, Request, ResponseWriter, SetupError,
    async_trait, client_write, next_or_failure, result_rcode,
};

use io::{Dio, Proto, Settings};
use listener::{Listener, ListenerSettings};
use msg::{Message, MessageType, encode_dnstap};

/// Upper bound of the write buffer multiple (MiB).
const MAX_MULTIPLE_TCP_WRITE_BUF: usize = 1024;
/// Upper bound of the queue multiple (× 10000 messages).
const MAX_MULTIPLE_QUEUE: usize = 4096;

/// One `dnstap` directive: where messages go and what they carry.
pub struct Tap {
    /// `full`: include the wire-format DNS messages.
    pub include_raw: bool,
    pub identity: Vec<u8>,
    pub version: Vec<u8>,
    pub extra_format: String,
    pub multiple_tcp_write_buf: usize,
    pub multiple_queue: usize,
    /// The block has the `metadata` plugin, so `{/label}` placeholders
    /// in `extra` resolve.
    metadata: bool,
    pub io: Option<Dio>,
    pub listener: Option<Listener>,
    /// Encoded messages, for tests.
    capture: Option<Mutex<Vec<Bytes>>>,
}

impl std::fmt::Debug for Tap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tap")
            .field("include_raw", &self.include_raw)
            .field("extra_format", &self.extra_format)
            .field("io", &self.io.as_ref().map(|d| d.settings.endpoint.clone()))
            .field("listener", &self.listener.as_ref().map(|l| l.settings.endpoint.clone()))
            .finish()
    }
}

impl Tap {
    /// `TapMessage`: send `m` with `extra` unexpanded.
    pub fn tap_message(&self, m: &Message) {
        let extra = (!self.extra_format.is_empty()).then_some(self.extra_format.as_bytes());
        self.tap_with_extra(m, extra);
    }

    /// `TapMessageWithMetadata`: send `m` with the placeholders of
    /// `extra` filled in from the request and its metadata.
    pub fn tap_message_with_metadata(&self, ctx: &Context, req: &Request, m: &Message) {
        if self.extra_format.is_empty() {
            self.tap_with_extra(m, None);
            return;
        }
        let extra = replace(&self.extra_format, self.metadata.then_some(ctx), req);
        self.tap_with_extra(m, Some(extra.as_bytes()));
    }

    fn tap_with_extra(&self, m: &Message, extra: Option<&[u8]>) {
        if self.io.is_none() && self.listener.is_none() && self.capture.is_none() {
            return;
        }
        let payload = Bytes::from(encode_dnstap(&self.identity, &self.version, extra, m));
        if let Some(io) = &self.io {
            io.dnstap(payload.clone());
        }
        if let Some(l) = &self.listener {
            l.dnstap(payload.clone());
        }
        if let Some(c) = &self.capture {
            c.lock().unwrap().push(payload);
        }
    }

    fn start(&self) {
        if let Some(io) = &self.io {
            io.connect();
        }
        if let Some(l) = &self.listener
            && let Err(e) = l.listen()
        {
            kerndns_core::error!(plugin = "dnstap", "Failed to start dnstap listener: {e}");
        }
    }

    fn stop(&self) {
        if let Some(io) = &self.io {
            io.close();
        }
        if let Some(l) = &self.listener {
            l.close();
        }
    }
}

/// The `dnstap` plugins of a server block, in Corefile order, for other
/// plugins to log to (`dnsserver.GetConfig(c).Handler("dnstap")`).
#[derive(Clone, Default)]
pub struct Taps(Arc<OnceLock<Vec<Arc<Tap>>>>);

impl Taps {
    /// The list of this block (created on first use).
    pub fn of(cfg: &mut BlockConfig) -> Taps {
        if cfg.extensions.get::<Taps>().is_none() {
            cfg.extensions.insert(Taps::default());
        }
        cfg.extensions.get::<Taps>().cloned().expect("inserted above")
    }

    /// The taps, if the block has any.
    pub fn get(&self) -> Option<&[Arc<Tap>]> {
        self.0.get().map(Vec::as_slice)
    }
}

/// `os.Hostname()`.
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// The version field: like CoreDNS's `CoreDNS-1.15.0`.
fn default_version() -> String {
    format!("KernDNS-{}", kerndns_core::VERSION)
}

/// Split `tcp://host:port` / `tls://host:port` / `[unix://]path`.
fn endpoint(s: &str) -> (Proto, String) {
    if let Some(rest) = s.strip_prefix("tls://") {
        (Proto::Tls, host_of_url(rest))
    } else if let Some(rest) = s.strip_prefix("tcp://") {
        (Proto::Tcp, host_of_url(rest))
    } else {
        (Proto::Unix, s.strip_prefix("unix://").unwrap_or(s).to_string())
    }
}

/// `url.Parse(...).Host`: up to the first `/`, `?` or `#`.
fn host_of_url(rest: &str) -> String {
    rest.split(['/', '?', '#']).next().unwrap_or("").to_string()
}

/// `parseConfig`.
pub fn parse_config(c: &mut Controller<'_>) -> Result<Vec<Tap>, SetupError> {
    let mut taps = Vec::new();
    let metadata = Metadata::enabled_in(c.config).is_some();
    while c.next() {
        let mut args = c.remaining_args();
        if args.is_empty() {
            return Err(c.arg_err());
        }
        let is_listener = args[0] == "listen";
        if is_listener {
            if args.len() < 2 {
                return Err(c.errf("dnstap listen requires an endpoint argument"));
            }
            args.remove(0);
        }
        let mut multiple_tcp_write_buf = 1usize;
        let mut multiple_queue = 1usize;
        if let Some(v) = args.get(2) {
            let n: i64 = v.parse().map_err(|e| {
                let msg = format!("dnstap: invalid MultipleTcpWriteBuf {v:?}: strconv.Atoi: parsing {v:?}: {e}");
                c.errf(msg)
            })?;
            if !(1..=MAX_MULTIPLE_TCP_WRITE_BUF as i64).contains(&n) {
                let msg = format!(
                    "dnstap: MultipleTcpWriteBuf must be between 1 and {MAX_MULTIPLE_TCP_WRITE_BUF} (MiB units): {n}"
                );
                return Err(c.errf(msg));
            }
            multiple_tcp_write_buf = n as usize;
        }
        if let Some(v) = args.get(3) {
            let n: i64 = v.parse().map_err(|e| {
                let msg = format!("dnstap: invalid MultipleQueue {v:?}: strconv.Atoi: parsing {v:?}: {e}");
                c.errf(msg)
            })?;
            if !(1..=MAX_MULTIPLE_QUEUE as i64).contains(&n) {
                let msg =
                    format!("dnstap: MultipleQueue must be between 1 and {MAX_MULTIPLE_QUEUE} (x10k messages): {n}");
                return Err(c.errf(msg));
            }
            multiple_queue = n as usize;
        }
        let (proto, ep) = endpoint(&args[0]);
        let mut io_settings = (!is_listener).then(|| Settings::new(proto, &ep, multiple_tcp_write_buf));
        let mut l_settings = is_listener.then(|| ListenerSettings::new(proto, &ep));
        let include_raw = args.get(1).is_some_and(|a| a == "full");
        let mut identity = hostname().into_bytes();
        let mut version = default_version().into_bytes();
        let mut extra_format = String::new();

        while c.next_block() {
            match c.val() {
                "skipverify" => {
                    if let Some(l) = l_settings.as_mut() {
                        l.skip_verify = true;
                    } else if let Some(s) = io_settings.as_mut() {
                        s.skip_verify = true;
                    }
                }
                "tls" => {
                    let Some(l) = l_settings.as_mut() else {
                        return Err(c.errf("tls directive only valid for listeners"));
                    };
                    let a = c.remaining_args();
                    if a.len() < 2 {
                        return Err(c.errf("tls requires cert and key file paths"));
                    }
                    l.cert_file = Some(a[0].clone());
                    l.key_file = Some(a[1].clone());
                    l.ca_file = a.get(2).cloned();
                }
                "identity" | "version" | "extra" => {
                    let key = c.val().to_string();
                    if !c.next_arg() {
                        return Err(c.arg_err());
                    }
                    let v = c.val().to_string();
                    match key.as_str() {
                        "identity" => identity = v.into_bytes(),
                        "version" => version = v.into_bytes(),
                        _ => extra_format = v,
                    }
                }
                other => {
                    let msg = format!("unknown property '{other}'");
                    return Err(c.errf(msg));
                }
            }
        }
        taps.push(Tap {
            include_raw,
            identity,
            version,
            extra_format,
            multiple_tcp_write_buf,
            multiple_queue,
            metadata,
            io: io_settings.map(|s| Dio::new(s, multiple_queue)),
            listener: l_settings.map(Listener::new),
            capture: None,
        });
    }
    Ok(taps)
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        "dnstap"
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let taps: Vec<Arc<Tap>> = parse_config(c)?.into_iter().map(Arc::new).collect();
        for t in &taps {
            let start = t.clone();
            c.on_startup(move || {
                start.start();
                Ok(())
            });
            let stop = t.clone();
            c.on_shutdown(move || stop.stop());
            let tap = t.clone();
            c.add_plugin(move |next| Arc::new(Dnstap { tap: tap.clone(), next }));
        }
        let _ = Taps::of(c.config).0.set(taps);
        Ok(())
    }
}

/// The handler of one `dnstap` directive.
pub struct Dnstap {
    tap: Arc<Tap>,
    next: Next,
}

/// Remembers what the rest of the chain wrote, to log it once the chain
/// returns (the `extra` field may need metadata set along the way).
struct TapWriter<'a> {
    inner: &'a mut dyn ResponseWriter,
    req: &'a Request,
    raw: bool,
    written: Vec<(SystemTime, Option<Vec<u8>>)>,
}

/// The response as the client gets it. CoreDNS packs it after the
/// server's `ScrubWriter` changed it in place: the client's EDNS echoed
/// and, over UDP, truncated to the client's buffer size.
fn client_wire(req: &Request, msg: &DnsMessage) -> Option<Vec<u8>> {
    let mut m = msg.clone();
    req.size_and_do(&mut m);
    if req.proto() == "udp" {
        kerndns_core::wire::truncate(&mut m, req.size() as usize);
    }
    kerndns_core::wire::to_wire(&m).ok()
}

#[async_trait]
impl ResponseWriter for TapWriter<'_> {
    async fn write_msg(&mut self, msg: DnsMessage) -> std::io::Result<()> {
        let wire = if self.raw { client_wire(self.req, &msg) } else { None };
        self.inner.write_msg(msg).await?;
        self.written.push((SystemTime::now(), wire));
        Ok(())
    }
}

impl Dnstap {
    fn tap_response(
        &self,
        ctx: &Context,
        req: &Request,
        query_time: SystemTime,
        at: SystemTime,
        wire: Option<Vec<u8>>,
    ) {
        let mut r = Message::new(MessageType::ClientResponse);
        r.set_query_time(query_time);
        r.set_response_time(at);
        r.set_query_address(req.remote, req.proto());
        r.response_message = wire;
        self.tap.tap_message_with_metadata(ctx, req, &r);
    }
}

#[async_trait]
impl Handler for Dnstap {
    fn name(&self) -> &'static str {
        "dnstap"
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let query_time = SystemTime::now();
        let raw = self.tap.include_raw;
        // the query is logged before anything is forwarded, so the
        // messages come out in order
        let mut q = Message::new(MessageType::ClientQuery);
        q.set_query_time(query_time);
        q.set_query_address(req.remote, req.proto());
        if raw {
            q.query_message = match &req.wire {
                Some(w) => Some(w.to_vec()),
                None => kerndns_core::wire::to_wire(&req.msg).ok(),
            };
        }
        self.tap.tap_message_with_metadata(ctx, req, &q);

        let mut rw = TapWriter {
            inner: w,
            req,
            raw,
            written: Vec::new(),
        };
        let res = next_or_failure("dnstap", &self.next, ctx, &mut rw, req).await;
        let written = std::mem::take(&mut rw.written);
        let rcode = result_rcode(&res);
        if written.is_empty() && !client_write(rcode) {
            // the server writes this error response after we return: log
            // what the client gets
            let wire = raw
                .then(|| kerndns_core::wire::to_wire(&req.error_reply(rcode)).ok())
                .flatten();
            self.tap_response(ctx, req, query_time, SystemTime::now(), wire);
        }
        for (at, wire) in written {
            self.tap_response(ctx, req, query_time, at, wire);
        }
        res
    }
}

/// Fill in the placeholders of `extra` like CoreDNS's replacer without a
/// recorder: request labels, `{/metadata}` (only with the `metadata`
/// plugin), and `-` for response labels and unknown metadata.
pub fn replace(format: &str, ctx: Option<&Context>, req: &Request) -> String {
    let mut out = String::with_capacity(format.len() + 32);
    let mut s = format;
    // find the right bracket, then backtrack to the left one, so "{ {x} }"
    // works
    while let Some(j) = s.find('}') {
        let Some(i) = s[..j].rfind('{') else {
            out.push_str(&s[..=j]);
            s = &s[j + 1..];
            continue;
        };
        let label = &s[i..=j];
        let value = label_value(label, ctx, req);
        match value {
            Some(v) => {
                out.push_str(&s[..i]);
                out.push_str(&v);
            }
            None => out.push_str(&s[..=j]),
        }
        s = &s[j + 1..];
    }
    out.push_str(s);
    out
}

fn bracket(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        v4 => v4.to_string(),
    }
}

fn label_value(label: &str, ctx: Option<&Context>, req: &Request) -> Option<String> {
    const EMPTY: &str = "-";
    Some(match label {
        "{type}" => req.qtype().to_string(),
        "{name}" => req.name(),
        "{class}" => req.qclass().to_string(),
        "{proto}" => req.proto().to_string(),
        "{size}" => match &req.wire {
            Some(w) => w.len(),
            None => kerndns_core::wire::to_wire(&req.msg).map(|w| w.len()).unwrap_or(0),
        }
        .to_string(),
        "{remote}" => bracket(req.ip()),
        "{port}" => req.port().to_string(),
        "{local}" => bracket(req.local.ip().to_canonical()),
        "{>id}" => req.id().to_string(),
        "{>opcode}" => u8::from(req.msg.metadata.op_code).to_string(),
        "{>do}" => req.do_bit().to_string(),
        "{>bufsize}" => req.size().to_string(),
        "{rcode}" | "{rsize}" | "{duration}" | "{>rflags}" => EMPTY.to_string(),
        _ => {
            let key = label.strip_prefix("{/")?.strip_suffix('}')?;
            ctx.and_then(|c| c.metadata.get(key).cloned())
                .unwrap_or_else(|| EMPTY.to_string())
        }
    })
}

#[cfg(test)]
mod tests;
