//! Runs CoreDNS's Go plugins inside a KernDNS chain.
//!
//! The plugins are compiled into one c-shared library
//! (`cargo xtask build-bridge`, source in `go/bridge`). [`Bridge::load`]
//! opens it, and [`Bridge::register`] adds a plugin factory for each Go
//! directive that has no Rust port (or that `prefer` names).
//!
//! A request crosses the boundary as packed DNS messages:
//! - [`GoPlugin`] calls `kb_serve`; the Go handler runs on a goroutine and
//!   reports back through three callbacks tagged with a token: a response
//!   it wrote, a call to its next plugin (the rest of the Rust chain), and
//!   its result.
//! - The callbacks only queue an event for the waiting Rust task, so no
//!   Go thread blocks in Rust and no Rust thread blocks in Go.
//! - A call to "next" runs the rest of the chain on the Rust side, captures
//!   what it writes, and hands it back with `kb_next_done`; the Go plugin
//!   then writes those messages through its own writer (so e.g. a Go cache
//!   sees them).

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_longlong};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use kerndns_core::proto::op::{Message, ResponseCode};
use kerndns_core::wire::to_wire;
use kerndns_core::{
    CaptureWriter, Context, Controller, Handler, HandlerResult, Next, PluginError, PluginFactory, Registry, Request,
    ResponseWriter, SetupError, async_trait, next_or_failure, result_rcode,
};
use libloading::Library;
use tokio::sync::mpsc;

type WriteFn = extern "C" fn(u64, *const u8, usize);
type NextFn = extern "C" fn(u64, u64, *const u8, usize);
type DoneFn = extern "C" fn(u64, c_int, *const c_char);

/// The library's exported functions.
struct Api {
    version: unsafe extern "C" fn() -> c_int,
    init: unsafe extern "C" fn(WriteFn, NextFn, DoneFn),
    free: unsafe extern "C" fn(*mut c_char),
    list_plugins: unsafe extern "C" fn() -> *mut c_char,
    directives: unsafe extern "C" fn() -> *mut c_char,
    setup: unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        *mut *mut c_char,
    ) -> c_longlong,
    startup: unsafe extern "C" fn(c_longlong, *mut *mut c_char) -> c_int,
    shutdown: unsafe extern "C" fn(c_longlong) -> c_int,
    ready: unsafe extern "C" fn(c_longlong) -> c_int,
    #[allow(clippy::type_complexity)]
    serve: unsafe extern "C" fn(
        c_longlong,
        u64,
        *const u8,
        usize,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
    ),
    #[allow(clippy::type_complexity)]
    serve_sync: unsafe extern "C" fn(
        c_longlong,
        u64,
        *const u8,
        usize,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
        *const c_char,
    ),
    next_done: unsafe extern "C" fn(u64, c_int, *const u8, usize, *const c_char),
    gather_metrics: unsafe extern "C" fn(*const c_char, *mut usize, *mut *mut c_char) -> *mut u8,
}

/// The loaded bridge library. It is never unloaded: a Go runtime can't be.
pub struct Bridge {
    api: Api,
    _lib: Library,
    plugins: Vec<String>,
    directives: Vec<String>,
}

static BRIDGE: OnceLock<Arc<Bridge>> = OnceLock::new();

const VERSION: c_int = 2;

/// What a Go plugin reported for one request.
enum Event {
    Write(Vec<u8>),
    Next(u64, Vec<u8>),
    Done(u16, String),
}

static PENDING: LazyLock<Mutex<HashMap<u64, mpsc::UnboundedSender<Event>>>> = LazyLock::new(Default::default);
static TOKENS: AtomicU64 = AtomicU64::new(1);

/// Tokens with this bit set point at a [`SyncCall`] on the stack of the
/// thread the callback runs on (synchronous mode).
const SYNC_BIT: u64 = 1 << 63;

fn send(token: u64, ev: Event) {
    if token & SYNC_BIT != 0 {
        // SAFETY: the token is the address of a SyncCall that lives for
        // the whole kb_serve_sync call, and callbacks for it only run on
        // that call's thread, inside it.
        let call = unsafe { &mut *((token & !SYNC_BIT) as *mut SyncCall<'_>) };
        call.event(ev);
        return;
    }
    if let Some(tx) = PENDING.lock().unwrap().get(&token) {
        let _ = tx.send(ev);
    }
}

/// # Safety (all three callbacks)
/// Go passes a pointer/length pair valid for the duration of the call; it
/// is copied before returning.
extern "C" fn on_write(token: u64, msg: *const u8, len: usize) {
    let b = if msg.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(msg, len) }.to_vec()
    };
    send(token, Event::Write(b));
}

extern "C" fn on_next(token: u64, next_token: u64, msg: *const u8, len: usize) {
    let b = if msg.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(msg, len) }.to_vec()
    };
    send(token, Event::Next(next_token, b));
}

extern "C" fn on_done(token: u64, rcode: c_int, err: *const c_char) {
    let e = if err.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(err) })
    };
    send(token, done_event(rcode, e));
}

/// The event for `on_done`.
fn done_event(rcode: c_int, err: Option<&CStr>) -> Event {
    let e = err.map(|e| e.to_string_lossy().into_owned()).unwrap_or_default();
    Event::Done(rcode as u16, e)
}

fn cstring(s: &str) -> CString {
    CString::new(s.replace('\0', "")).expect("no NUL bytes")
}

impl Bridge {
    /// Load the bridge library once per process; later calls return it.
    pub fn load(path: &Path) -> Result<Arc<Bridge>, String> {
        if let Some(b) = BRIDGE.get() {
            return Ok(b.clone());
        }
        let err = |e: libloading::Error| format!("loading Go bridge {}: {e}", path.display());
        // SAFETY: loading a library runs its initializers; the bridge is
        // built by `cargo xtask build-bridge` for this purpose.
        let lib = unsafe { Library::new(path) }.map_err(err)?;
        macro_rules! sym {
            ($n:literal) => {
                // SAFETY: the symbol types match go/bridge/bridge.go.
                *unsafe { lib.get($n) }.map_err(err)?
            };
        }
        let api = Api {
            version: sym!(b"kb_version"),
            init: sym!(b"kb_init"),
            free: sym!(b"kb_free"),
            list_plugins: sym!(b"kb_list_plugins"),
            directives: sym!(b"kb_directives"),
            setup: sym!(b"kb_setup"),
            startup: sym!(b"kb_startup"),
            shutdown: sym!(b"kb_shutdown"),
            ready: sym!(b"kb_ready"),
            serve: sym!(b"kb_serve"),
            serve_sync: sym!(b"kb_serve_sync"),
            next_done: sym!(b"kb_next_done"),
            gather_metrics: sym!(b"kb_gather_metrics"),
        };
        // SAFETY: plain calls into the bridge; returned strings are freed
        // with kb_free.
        let (plugins, directives) = unsafe {
            let v = (api.version)();
            if v != VERSION {
                return Err(format!(
                    "Go bridge {} has interface version {v}, KernDNS needs {VERSION}",
                    path.display()
                ));
            }
            (api.init)(on_write, on_next, on_done);
            let list = |p: *mut c_char| {
                let s = CStr::from_ptr(p).to_string_lossy().into_owned();
                (api.free)(p);
                parse_string_list(&s)
            };
            (list((api.list_plugins)()), list((api.directives)()))
        };
        let b = Arc::new(Bridge {
            api,
            _lib: lib,
            plugins,
            directives,
        });
        let _ = BRIDGE.set(b.clone());
        kerndns_core::metrics::set_extra_gatherer(gather);
        Ok(BRIDGE.get().expect("set above").clone())
    }

    /// The directives compiled into the bridge.
    pub fn plugins(&self) -> &[String] {
        &self.plugins
    }

    /// Register a factory for every Go directive that has no Rust port,
    /// and for those in `prefer` even if it has. Returns the names used.
    ///
    /// Directives the bridge's `dnsserver.Directives` adds (out-of-tree
    /// plugins) join the execution order where that list puts them.
    pub fn register(self: &Arc<Self>, registry: &mut Registry, prefer: &[String]) -> Vec<&'static str> {
        kerndns_core::order::add_directives(&self.directives);
        let mut used = Vec::new();
        for p in &self.plugins {
            if registry.get(p).is_some() && !prefer.contains(p) {
                continue;
            }
            let name: &'static str = Box::leak(p.clone().into_boxed_str());
            registry.register(GoFactory {
                bridge: self.clone(),
                name,
            });
            used.push(name);
        }
        used
    }

    fn setup(&self, name: &str, text: &str, keys: &[String], root: &str) -> Result<i64, String> {
        let keys_json = format!(
            "[{}]",
            keys.iter().map(|k| json_string(k)).collect::<Vec<_>>().join(",")
        );
        let (n, t, k, r) = (cstring(name), cstring(text), cstring(&keys_json), cstring(root));
        let mut err: *mut c_char = std::ptr::null_mut();
        // SAFETY: all strings live across the call; err is freed with kb_free.
        let h = unsafe { (self.api.setup)(n.as_ptr(), t.as_ptr(), k.as_ptr(), r.as_ptr(), &mut err) };
        if h == 0 {
            return Err(self.take(err));
        }
        Ok(h)
    }

    fn take(&self, p: *mut c_char) -> String {
        if p.is_null() {
            return "unknown error".into();
        }
        // SAFETY: p came from C.CString in the bridge.
        unsafe {
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            (self.api.free)(p);
            s
        }
    }

    fn startup(&self, h: i64) -> Result<(), String> {
        let mut err: *mut c_char = std::ptr::null_mut();
        // SAFETY: as in setup.
        if unsafe { (self.api.startup)(h, &mut err) } != 0 {
            return Err(self.take(err));
        }
        Ok(())
    }

    fn shutdown(&self, h: i64) {
        // SAFETY: plain call.
        unsafe { (self.api.shutdown)(h) };
    }

    fn ready(&self, h: i64) -> bool {
        // SAFETY: plain call.
        unsafe { (self.api.ready)(h) == 1 }
    }
}

/// The Go registry for one scrape, in the format `accept` asks for.
fn gather(accept: &str) -> Option<(String, Vec<u8>)> {
    let b = BRIDGE.get()?;
    let a = cstring(accept);
    let mut n = 0usize;
    let mut ct: *mut c_char = std::ptr::null_mut();
    // SAFETY: the returned buffer is malloc'd by the bridge and n bytes long.
    unsafe {
        let p = (b.api.gather_metrics)(a.as_ptr(), &mut n, &mut ct);
        let body = if p.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(p, n).to_vec()
        };
        if !p.is_null() {
            (b.api.free)(p as *mut c_char);
        }
        Some((b.take(ct), body))
    }
}

fn json_string(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// The JSON array of strings the bridge returns for its plugin list.
fn parse_string_list(s: &str) -> Vec<String> {
    s.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|x| x.trim().trim_matches('"').to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// Corefile text for the directive's tokens, line by line, quoting tokens
/// that caddy's lexer (on the Go side) would otherwise split or drop.
///
/// That lexer takes a token verbatim (backslashes included) unless it
/// contains white space or `#` or starts with `"`. Inside quotes, `\"` is
/// a quote and any other backslash pair stays as it is, so only quotes are
/// escaped. (A token that needs quotes and has an odd run of backslashes
/// before a quote or at its end can't be written for that lexer; it can't
/// come from that lexer either.)
pub fn render_tokens(tokens: &[kerndns_corefile::Token]) -> String {
    let mut out = String::new();
    let mut line = None;
    for t in tokens {
        if line.as_ref().is_some_and(|l| *l != (t.file.clone(), t.line)) {
            out.push('\n');
        } else if line.is_some() {
            out.push(' ');
        }
        line = Some((t.file.clone(), t.line));
        let plain =
            !t.text.is_empty() && !t.text.starts_with('"') && !t.text.chars().any(|c| c.is_whitespace() || c == '#');
        if plain {
            out.push_str(&t.text);
        } else {
            out.push('"');
            for c in t.text.chars() {
                if c == '"' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        }
    }
    out.push('\n');
    out
}

struct GoFactory {
    bridge: Arc<Bridge>,
    name: &'static str,
}

/// Plugins served in synchronous mode (`-bridge.sync`).
static SYNC: OnceLock<Vec<String>> = OnceLock::new();

/// Serve these Go plugins on the calling thread instead of a goroutine:
/// no thread hand-offs per request, but a plugin that waits on the network
/// blocks a runtime worker meanwhile. Meant for CPU-only plugins.
pub fn set_sync(plugins: Vec<String>) {
    let _ = SYNC.set(plugins);
}

impl PluginFactory for GoFactory {
    fn name(&self) -> &'static str {
        self.name
    }

    fn bridged(&self) -> bool {
        true
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let text = render_tokens(c.tokens());
        let keys: Vec<String> = c.config.keys.iter().map(|k| k.to_string()).collect();
        let root = c
            .config
            .root
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let prefix = format!("plugin/{}: ", self.name);
        let h = self
            .bridge
            .setup(self.name, &text, &keys, &root)
            .map_err(|e| SetupError::new(self.name, e.strip_prefix(&prefix).unwrap_or(&e)))?;
        let (b, name) = (self.bridge.clone(), self.name);
        c.on_startup(move || b.startup(h).map_err(|e| format!("plugin/{name}: {e}")));
        let b = self.bridge.clone();
        c.on_shutdown(move || b.shutdown(h));
        let b = self.bridge.clone();
        kerndns_core::readiness::register(self.name, move || b.ready(h));
        let (b, name) = (self.bridge.clone(), self.name);
        let sync = SYNC.get().is_some_and(|s| s.iter().any(|p| p == name));
        c.add_plugin(move |next| {
            Arc::new(GoPlugin {
                bridge: b.clone(),
                handle: h,
                name,
                next,
                sync,
            })
        });
        Ok(())
    }
}

/// A Go plugin in the chain.
pub struct GoPlugin {
    bridge: Arc<Bridge>,
    handle: i64,
    name: &'static str,
    next: Next,
    sync: bool,
}

/// One synchronous call: what the Go plugin wrote and returned, and what
/// running the rest of the chain needs if it calls next.
struct SyncCall<'a> {
    plugin: &'a GoPlugin,
    ctx: *mut Context,
    req: &'a Request,
    writes: Vec<Vec<u8>>,
    done: Option<(u16, String)>,
}

impl SyncCall<'_> {
    fn event(&mut self, ev: Event) {
        match ev {
            Event::Write(b) => self.writes.push(b),
            Event::Done(code, err) => self.done = Some((code, err)),
            Event::Next(nt, b) => {
                // SAFETY: serve_dns holds the &mut Context and doesn't touch
                // it while the synchronous call runs.
                let ctx = unsafe { &mut *self.ctx };
                let fut = run_next(self.plugin.name, &self.plugin.next, ctx, self.req, &b);
                let (code, out, err) = tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(fut));
                let err = cstring(&err);
                // SAFETY: as in serve_dns; the Go side doesn't keep the buffer.
                unsafe {
                    (self.plugin.bridge.api.next_done)(nt, c_int::from(code), out.as_ptr(), out.len(), err.as_ptr())
                };
            }
        }
    }
}

/// Unregisters the token if the request is abandoned midway.
struct Pending(u64);

impl Drop for Pending {
    fn drop(&mut self) {
        PENDING.lock().unwrap().remove(&self.0);
    }
}

fn meta_json(ctx: &Context) -> String {
    let items: Vec<String> = ctx
        .metadata
        .iter()
        .map(|(k, v)| format!("{}:{}", json_string(k), json_string(v)))
        .collect();
    format!("{{{}}}", items.join(","))
}

fn rcode(code: u16) -> ResponseCode {
    ResponseCode::from((code >> 4) as u8, (code & 0xF) as u8)
}

#[async_trait]
impl Handler for GoPlugin {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn serve_dns(&self, ctx: &mut Context, w: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
        let wire = match &req.wire {
            Some(b) => b.to_vec(),
            None => to_wire(&req.msg).map_err(|e| PluginError::servfail(self.name, e.to_string()))?,
        };
        let proto = if req.proto() == "udp" { "udp" } else { "tcp" };
        let (remote, local) = (cstring(&req.remote.to_string()), cstring(&req.local.to_string()));
        let (proto, server, meta) = (cstring(proto), cstring(&ctx.server), cstring(&meta_json(ctx)));
        // block_in_place (for a call to next) needs the multi-thread runtime
        let multi = tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
        if self.sync && multi {
            let (writes, done) = self.call_sync(ctx, req, &wire, [&remote, &local, &proto, &server, &meta]);
            for b in writes {
                write_from_go(self.name, w, &b).await?;
            }
            let (code, err) = done.unwrap_or((2, "Go plugin returned no result".into()));
            return done_result(self.name, code, err);
        }
        let token = TOKENS.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::unbounded_channel();
        PENDING.lock().unwrap().insert(token, tx);
        let _pending = Pending(token);
        // SAFETY: the bridge copies every argument before returning.
        unsafe {
            (self.bridge.api.serve)(
                self.handle,
                token,
                wire.as_ptr(),
                wire.len(),
                remote.as_ptr(),
                local.as_ptr(),
                proto.as_ptr(),
                server.as_ptr(),
                meta.as_ptr(),
            )
        };
        let next_done = |nt: u64, code: u16, out: &[u8], err: &CStr| {
            // SAFETY: as above.
            unsafe { (self.bridge.api.next_done)(nt, c_int::from(code), out.as_ptr(), out.len(), err.as_ptr()) };
        };
        drive(self.name, &self.next, ctx, w, req, &mut rx, next_done).await
    }
}

/// A response the Go plugin wrote: pass it on to `w`. An unparsable one is
/// logged and dropped.
async fn write_from_go(name: &'static str, w: &mut dyn ResponseWriter, b: &[u8]) -> Result<(), PluginError> {
    match Message::from_vec(b) {
        Ok(m) => w
            .write_msg(m)
            .await
            .map_err(|e| PluginError::servfail(name, e.to_string())),
        Err(e) => {
            kerndns_core::error!(plugin = name, "unparsable response from Go: {e}");
            Ok(())
        }
    }
}

/// The Go plugin's result: its rcode and error text.
fn done_result(name: &'static str, code: u16, err: String) -> HandlerResult {
    let rc = rcode(code);
    if err.is_empty() {
        return Ok(rc);
    }
    Err(PluginError::new(name, rc, err))
}

/// Handle the events of one asynchronous request until the Go plugin is
/// done; `next_done` answers its calls to next.
async fn drive(
    name: &'static str,
    next: &Next,
    ctx: &mut Context,
    w: &mut dyn ResponseWriter,
    req: &Request,
    rx: &mut mpsc::UnboundedReceiver<Event>,
    next_done: impl Fn(u64, u16, &[u8], &CStr),
) -> HandlerResult {
    while let Some(ev) = rx.recv().await {
        match ev {
            Event::Write(b) => write_from_go(name, w, &b).await?,
            Event::Next(nt, b) => {
                let (code, out, err) = run_next(name, next, ctx, req, &b).await;
                next_done(nt, code, &out, &cstring(&err));
            }
            Event::Done(code, err) => return done_result(name, code, err),
        }
    }
    Err(PluginError::servfail(name, "Go bridge closed the request"))
}

impl GoPlugin {
    /// One synchronous call into Go; returns what it wrote and its result.
    fn call_sync(
        &self,
        ctx: &mut Context,
        req: &Request,
        wire: &[u8],
        [remote, local, proto, server, meta]: [&CString; 5],
    ) -> (Vec<Vec<u8>>, Option<(u16, String)>) {
        let mut call = SyncCall {
            plugin: self,
            ctx: ctx as *mut Context,
            req,
            writes: Vec::new(),
            done: None,
        };
        let token = (&mut call as *mut SyncCall<'_> as u64) | SYNC_BIT;
        // SAFETY: arguments are copied by the bridge; `call` outlives the
        // call, during which its callbacks run on this thread.
        unsafe {
            (self.bridge.api.serve_sync)(
                self.handle,
                token,
                wire.as_ptr(),
                wire.len(),
                remote.as_ptr(),
                local.as_ptr(),
                proto.as_ptr(),
                server.as_ptr(),
                meta.as_ptr(),
            )
        };
        (call.writes, call.done)
    }
}

/// The rest of the chain for the Go plugin's `Next`: (rcode, written
/// messages each prefixed with a 2-byte length, error text).
async fn run_next(
    name: &'static str,
    next: &Next,
    ctx: &mut Context,
    req: &Request,
    wire: &[u8],
) -> (u16, Vec<u8>, String) {
    let mut r = req.clone();
    match Message::from_vec(wire) {
        // Rust plugins rely on the server's guarantee of one question
        // (`Request::query`); a Go plugin can call its next plugin with a
        // message without one, so answer SERVFAIL like the server does
        Ok(m) if m.queries.is_empty() => return (2, Vec::new(), "message without a question".into()),
        Ok(m) => r.msg = m,
        Err(e) => return (2, Vec::new(), e.to_string()),
    }
    r.wire = Some(Arc::from(wire));
    let mut cw = CaptureWriter::new();
    let res = next_or_failure(name, next, ctx, &mut cw, &r).await;
    let code = u16::from(result_rcode(&res));
    let err = res.err().map(|e| e.msg).unwrap_or_default();
    let mut out = Vec::new();
    for m in &cw.msgs {
        if let Ok(b) = to_wire(m)
            && let Ok(n) = u16::try_from(b.len())
        {
            out.extend_from_slice(&n.to_be_bytes());
            out.extend_from_slice(&b);
        }
    }
    (code, out, err)
}

/// Entry points for the fuzz targets in `fuzz/`: what the Rust side does
/// with data coming back from Go, without loading the library.
#[doc(hidden)]
pub mod fuzz {
    use super::*;

    /// One callback from the Go side.
    pub enum Callback<'a> {
        /// `on_write`: a response the Go plugin wrote.
        Write(&'a [u8]),
        /// `on_next`: the Go plugin calls its next plugin with this message.
        Next(u64, &'a [u8]),
        /// `on_done`: its rcode and error text (NUL-terminated, or none).
        Done(c_int, Option<&'a CStr>),
    }

    /// Feed `callbacks` to one request as the async path would receive
    /// them; returns the plugin's result and what each `next_done` got.
    pub async fn replay(
        next: &Next,
        ctx: &mut Context,
        w: &mut dyn ResponseWriter,
        req: &Request,
        callbacks: &[Callback<'_>],
    ) -> (HandlerResult, Vec<(u64, u16, Vec<u8>)>) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        for c in callbacks {
            let ev = match c {
                Callback::Write(b) => Event::Write(b.to_vec()),
                Callback::Next(t, b) => Event::Next(*t, b.to_vec()),
                Callback::Done(code, err) => done_event(*code, *err),
            };
            let _ = tx.send(ev);
        }
        drop(tx);
        let done = std::cell::RefCell::new(Vec::new());
        let res = drive("fuzz", next, ctx, w, req, &mut rx, |t, code, out, _err| {
            done.borrow_mut().push((t, code, out.to_vec()))
        })
        .await;
        (res, done.into_inner())
    }

    /// The bridge's plugin list as `Bridge::load` parses it.
    pub fn plugin_list(s: &str) -> Vec<String> {
        parse_string_list(s)
    }

    /// The token texts caddy's lexer (`github.com/coredns/caddy`
    /// `caddyfile/lexer.go`, which the Go side uses on
    /// [`render_tokens`]'s output) reads from `input`.
    pub fn caddy_lex(input: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut it = input.chars();
        loop {
            let mut val = String::new();
            let (mut comment, mut quoted, mut escaped) = (false, false, false);
            let done = loop {
                let Some(ch) = it.next() else {
                    break !val.is_empty();
                };
                if quoted {
                    if !escaped {
                        if ch == '\\' {
                            escaped = true;
                            continue;
                        } else if ch == '"' {
                            break true;
                        }
                    }
                    if escaped && ch != '"' {
                        val.push('\\');
                    }
                    val.push(ch);
                    escaped = false;
                    continue;
                }
                if ch.is_whitespace() {
                    if ch == '\r' {
                        continue;
                    }
                    if ch == '\n' {
                        comment = false;
                    }
                    if !val.is_empty() {
                        break true;
                    }
                    continue;
                }
                if ch == '#' {
                    comment = true;
                }
                if comment {
                    continue;
                }
                if val.is_empty() && ch == '"' {
                    quoted = true;
                    continue;
                }
                val.push(ch);
            };
            if !done {
                return out;
            }
            out.push(val);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerndns_core::Protocol;
    use kerndns_core::proto::op::{MessageType, OpCode, Query};
    use kerndns_core::proto::rr::{Name, RecordType};
    use kerndns_corefile::Token;

    fn tok(text: &str, line: usize) -> Token {
        Token {
            text: text.into(),
            file: Arc::from("Corefile"),
            line,
        }
    }

    #[test]
    fn renders_directive_text() {
        let t = [
            tok("etcd", 1),
            tok("skydns.local", 1),
            tok("{", 1),
            tok("path", 2),
            tok("/sky dns", 2),
            tok("endpoint", 3),
            tok("http://localhost:2379", 3),
            tok("}", 4),
        ];
        assert_eq!(
            render_tokens(&t),
            "etcd skydns.local {\npath \"/sky dns\"\nendpoint http://localhost:2379\n}\n"
        );
    }

    /// Found by `fuzz/` (bridge target): backslashes were escaped inside
    /// quotes, but caddy's lexer keeps `\\` as two backslashes, so a Go
    /// plugin got `a\\.b` for the regex `a\.b`.
    #[test]
    fn rendered_tokens_lex_back() {
        let t = [
            tok("rewrite", 1),
            tok(r"a\.b", 1),
            tok(r"with space\d", 1),
            tok(r#"q"uote"#, 1),
            tok(r#""lead"#, 1),
            tok("has#hash", 1),
            tok("", 1),
            tok(r"\\", 2),
        ];
        let rendered = render_tokens(&t);
        assert_eq!(
            rendered,
            "rewrite a\\.b \"with space\\d\" q\"uote \"\\\"lead\" \"has#hash\" \"\"\n\\\\\n"
        );
        let texts: Vec<String> = t.iter().map(|t| t.text.clone()).collect();
        assert_eq!(fuzz::caddy_lex(&rendered), texts);
    }

    #[test]
    fn caddy_lexer() {
        assert_eq!(
            fuzz::caddy_lex("a \"b c\" \"d\\\"e\" \"f\\g\" # x\nh\"i ``"),
            vec!["a", "b c", "d\"e", "f\\g", "h\"i", "``"]
        );
    }

    /// A next plugin that reads the question, as every Rust plugin may.
    struct ReadsQuestion;

    #[async_trait]
    impl Handler for ReadsQuestion {
        fn name(&self) -> &'static str {
            "reads-question"
        }
        async fn serve_dns(&self, _: &mut Context, _: &mut dyn ResponseWriter, req: &Request) -> HandlerResult {
            let _ = req.qname();
            Ok(ResponseCode::NoError)
        }
    }

    /// Found by the CI fuzz job (bridge target): a Go plugin calling its
    /// next plugin with a message without a question panicked the Rust
    /// chain at `Request::query`.
    #[tokio::test]
    async fn next_without_question_is_servfail() {
        let a: std::net::SocketAddr = "127.0.0.1:53".parse().unwrap();
        let mut q = Message::new(1, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(Name::from_ascii("example.org.").unwrap(), RecordType::A));
        let req = Request::new(q, a, a, Protocol::Udp);
        let next: Next = Some(Arc::new(ReadsQuestion));
        let empty = Message::new(2, MessageType::Query, OpCode::Query).to_vec().unwrap();
        let mut ctx = Context::new(".", "dns://:53");
        let (code, out, err) = run_next("test", &next, &mut ctx, &req, &empty).await;
        assert_eq!((code, out.is_empty()), (2, true));
        assert!(err.contains("question"), "{err}");
    }

    #[test]
    fn plugin_list() {
        assert_eq!(parse_string_list(r#"["etcd","whoami"]"#), vec!["etcd", "whoami"]);
        assert!(parse_string_list("[]").is_empty());
    }
}
