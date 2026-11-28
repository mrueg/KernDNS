//! `pprof`: profiling endpoints under `/debug/pprof`. Port of
//! `plugin/pprof`, with the Corefile syntax and errors of CoreDNS.
//!
//! ```text
//! pprof [ADDRESS] {
//!    block [RATE]
//! }
//! ```
//!
//! CoreDNS serves Go's `net/http/pprof`. KernDNS has no Go runtime to
//! profile, so it serves what applies to a Rust process, in the same
//! format: `/debug/pprof/profile?seconds=N` is a CPU profile in pprof's
//! protobuf format (gzipped, sampled at 100 Hz with the `pprof` crate),
//! readable by `go tool pprof` and other pprof viewers;
//! `/debug/pprof/cmdline` is the command line. Go-only profiles (heap,
//! goroutine, block, mutex, trace, ...) answer 404, and `block` is
//! accepted but has no effect.

use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use kerndns_core::{Controller, PluginFactory, SetupError};
use tokio::net::TcpListener;

use crate::http::{listen_addr, split_host_port};

const NAME: &str = "pprof";
const DEFAULT_ADDR: &str = "localhost:6053";
const PATH: &str = "/debug/pprof";

/// Parsed configuration.
#[derive(Debug, PartialEq, Eq)]
struct Config {
    addr: String,
    /// `block RATE`: Go's block profile rate; recorded, no effect.
    rate_block: i64,
}

fn parse(c: &mut Controller<'_>) -> Result<Config, SetupError> {
    let mut cfg = Config {
        addr: DEFAULT_ADDR.into(),
        rate_block: 0,
    };
    let mut i = 0;
    while c.next() {
        if i > 0 {
            return Err(SetupError::new(
                NAME,
                "this plugin can only be used once per Server Block",
            ));
        }
        i += 1;
        let args = c.remaining_args();
        if args.len() == 1 {
            cfg.addr = args[0].clone();
            if let Err(e) = split_host_port(&cfg.addr) {
                return Err(c.errf(e));
            }
        }
        if args.len() > 1 {
            return Err(c.arg_err());
        }
        while c.next_block() {
            match c.val() {
                "block" => {
                    let args = c.remaining_args();
                    if args.len() > 1 {
                        return Err(c.arg_err());
                    }
                    cfg.rate_block = 1;
                    if let Some(a) = args.first() {
                        cfg.rate_block = a
                            .parse()
                            .map_err(|_| c.errf(format!("property 'block' invalid integer value '{a}'")))?;
                    }
                }
                other => {
                    let msg = format!("unknown property '{other}'");
                    return Err(c.errf(msg));
                }
            }
        }
    }
    Ok(cfg)
}

/// Only one CPU profile can run at a time (one SIGPROF timer).
static PROFILING: Mutex<()> = Mutex::new(());

/// A CPU profile of the whole process for `secs` seconds, as gzipped
/// pprof protobuf.
async fn cpu_profile(secs: u64) -> Result<Vec<u8>, String> {
    // the profiler guard can't cross threads: run it on a blocking thread
    tokio::task::spawn_blocking(move || {
        let _lock = PROFILING
            .try_lock()
            .map_err(|_| "Could not enable CPU profiling: cpu profiling already in use".to_string())?;
        let guard = ::pprof::ProfilerGuardBuilder::default()
            .frequency(100)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()
            .map_err(|e| format!("Could not enable CPU profiling: {e}"))?;
        std::thread::sleep(Duration::from_secs(secs));
        let report = guard.report().build().map_err(|e| e.to_string())?;
        drop(guard);
        gzip(&encode_profile(&report))
    })
    .await
    .map_err(|e| e.to_string())?
}

fn gzip(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(raw).map_err(|e| e.to_string())?;
    gz.finish().map_err(|e| e.to_string())
}

/// Minimal protobuf writer for `perftools.profiles.Profile`.
#[derive(Default)]
struct Pb(Vec<u8>);

impl Pb {
    fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.0.push((v as u8) | 0x80);
            v >>= 7;
        }
        self.0.push(v as u8);
    }

    fn key(&mut self, field: u32, wire: u8) {
        self.varint(u64::from(field << 3 | u32::from(wire)));
    }

    fn uint(&mut self, field: u32, v: u64) {
        if v != 0 {
            self.key(field, 0);
            self.varint(v);
        }
    }

    fn bytes(&mut self, field: u32, b: &[u8]) {
        self.key(field, 2);
        self.varint(b.len() as u64);
        self.0.extend_from_slice(b);
    }

    fn packed(&mut self, field: u32, vs: &[u64]) {
        let mut inner = Pb::default();
        for v in vs {
            inner.varint(*v);
        }
        self.bytes(field, &inner.0);
    }
}

/// The report as a pprof `Profile`: two sample values (samples/count and
/// cpu/nanoseconds), one location and function per symbol.
fn encode_profile(report: &::pprof::Report) -> Vec<u8> {
    let mut strings: Vec<String> = vec![String::new()];
    let mut string_ids: HashMap<String, u64> = HashMap::from([(String::new(), 0)]);
    let mut intern = |s: String| -> u64 {
        if let Some(id) = string_ids.get(&s) {
            return *id;
        }
        let id = strings.len() as u64;
        strings.push(s.clone());
        string_ids.insert(s, id);
        id
    };
    let period = 1_000_000_000 / u64::try_from(report.timing.frequency.max(1)).unwrap_or(100);
    let mut out = Pb::default();
    let value_type = |intern: &mut dyn FnMut(String) -> u64, ty: &str, unit: &str| {
        let mut vt = Pb::default();
        vt.uint(1, intern(ty.into()));
        vt.uint(2, intern(unit.into()));
        vt.0
    };
    let st1 = value_type(&mut intern, "samples", "count");
    let st2 = value_type(&mut intern, "cpu", "nanoseconds");
    out.bytes(1, &st1);
    out.bytes(1, &st2);

    // function ids by (name, file); location ids by (function, line)
    let mut functions: HashMap<(String, String), u64> = HashMap::new();
    let mut function_pb = Pb::default();
    let mut locations: HashMap<(u64, u32), u64> = HashMap::new();
    let mut location_pb = Pb::default();
    for (frames, count) in &report.data {
        let mut ids = Vec::new();
        for frame in &frames.frames {
            for sym in frame {
                let (name, file) = (sym.name(), sym.filename().into_owned());
                let next_fn = functions.len() as u64 + 1;
                let fid = *functions.entry((name.clone(), file.clone())).or_insert_with(|| {
                    let mut f = Pb::default();
                    f.uint(1, next_fn);
                    f.uint(2, intern(name.clone()));
                    f.uint(3, intern(sym.sys_name().into_owned()));
                    f.uint(4, intern(file.clone()));
                    function_pb.bytes(5, &f.0);
                    next_fn
                });
                let line = sym.lineno.unwrap_or(0);
                let next_loc = locations.len() as u64 + 1;
                let lid = *locations.entry((fid, line)).or_insert_with(|| {
                    let mut l = Pb::default();
                    l.uint(1, next_loc);
                    let mut ln = Pb::default();
                    ln.uint(1, fid);
                    ln.uint(2, u64::from(line));
                    l.bytes(4, &ln.0);
                    location_pb.bytes(4, &l.0);
                    next_loc
                });
                ids.push(lid);
            }
        }
        let n = u64::try_from(*count).unwrap_or(0);
        let mut s = Pb::default();
        s.packed(1, &ids);
        s.packed(2, &[n, n * period]);
        out.bytes(2, &s.0);
    }
    out.0.extend_from_slice(&location_pb.0);
    out.0.extend_from_slice(&function_pb.0);
    let start = report
        .timing
        .start_time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let pt = value_type(&mut intern, "cpu", "nanoseconds");
    for s in &strings {
        out.bytes(6, s.as_bytes());
    }
    out.uint(9, start.as_nanos() as u64);
    out.uint(10, report.timing.duration.as_nanos() as u64);
    out.bytes(11, &pt);
    out.uint(12, period);
    out.0
}

fn response(status: u16, ctype: &str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", ctype)
        .header("X-Content-Type-Options", "nosniff")
        .body(Full::new(body.into()))
        .expect("valid response")
}

const INDEX: &str = "<html>
<head>
<title>/debug/pprof/</title>
</head>
<body>
/debug/pprof/
<br>
<p>Set debug=1 as a query parameter to export in legacy text format</p>
<br>
Types of profiles available:
<table>
<thead><td>Count</td><td>Profile</td></thead>
</table>
<a href=\"cmdline\">cmdline</a>
<br>
<a href=\"profile\">profile</a>
<br>
<br>
<p>
Profile Descriptions:
<ul>
<li><div class=profile-name>cmdline: </div> The command line invocation of the current program</li>
<li><div class=profile-name>profile: </div> CPU profile. You can specify the duration in the seconds GET parameter. After you get the profile file, use the go tool pprof command to investigate the profile.</li>
</ul>
</p>
</body>
</html>
";

async fn route(path: &str, query: Option<&str>) -> Response<Full<Bytes>> {
    let text = "text/plain; charset=utf-8";
    match path {
        PATH => Response::builder()
            .status(302)
            .header("Location", format!("{PATH}/"))
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(format!("<a href=\"{PATH}/\">Found</a>.\n\n"))))
            .expect("valid response"),
        "/debug/pprof/" => response(200, "text/html; charset=utf-8", INDEX),
        "/debug/pprof/cmdline" => {
            let args: Vec<String> = std::env::args().collect();
            response(200, text, args.join("\0"))
        }
        "/debug/pprof/profile" => {
            let secs = query
                .unwrap_or("")
                .split('&')
                .find_map(|kv| kv.strip_prefix("seconds="))
                .map(|v| v.parse::<u64>().unwrap_or(0))
                .filter(|s| *s > 0)
                .unwrap_or(30);
            match cpu_profile(secs).await {
                Ok(body) => Response::builder()
                    .status(200)
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Disposition", "attachment; filename=\"profile\"")
                    .header("X-Content-Type-Options", "nosniff")
                    .body(Full::new(Bytes::from(body)))
                    .expect("valid response"),
                Err(e) => response(500, text, format!("{e}\n")),
            }
        }
        _ if path.starts_with("/debug/pprof/") => response(404, text, "Unknown profile\n"),
        _ => response(404, text, "404 page not found\n"),
    }
}

/// The running endpoint.
struct Server {
    task: tokio::task::AbortHandle,
}

fn start(addr: &str) -> std::io::Result<Server> {
    let addr = listen_addr(addr);
    let std_listener = match std::net::TcpListener::bind(&addr).map_err(crate::http::go_bind_error) {
        Ok(l) => l,
        Err(e) if addr.starts_with("[::]") => {
            std::net::TcpListener::bind(addr.replacen("[::]", "0.0.0.0", 1)).map_err(|_| e)?
        }
        Err(e) => return Err(e),
    };
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    Ok::<_, Infallible>(route(req.uri().path(), req.uri().query()).await)
                });
                let _ = http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
            });
        }
    });
    Ok(Server {
        task: task.abort_handle(),
    })
}

pub struct Setup;

impl PluginFactory for Setup {
    fn name(&self) -> &'static str {
        NAME
    }

    fn setup(&self, c: &mut Controller<'_>) -> Result<(), SetupError> {
        let cfg = parse(c)?;
        let srv: Arc<Mutex<Option<Server>>> = Arc::default();
        let srv2 = srv.clone();
        c.on_startup(move || {
            match start(&cfg.addr) {
                Ok(s) => *srv.lock().unwrap() = Some(s),
                Err(e) => {
                    let e = format!("listen tcp {}: {e}", cfg.addr);
                    kerndns_core::error!(plugin = NAME, "Failed to start pprof handler: {e}");
                    return Err(e);
                }
            }
            if cfg.rate_block != 0 {
                kerndns_core::warning!(
                    plugin = NAME,
                    "block profiling is a Go runtime feature; KernDNS serves CPU profiles only"
                );
            }
            Ok(())
        });
        c.on_shutdown(move || {
            if let Some(s) = srv2.lock().unwrap().take() {
                s.task.abort();
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;

    // setup_test.go: TestPProf
    #[test]
    fn setup() {
        let tests = [
            ("pprof", false),
            ("pprof 1.2.3.4:1234", false),
            ("pprof :1234", false),
            ("pprof :1234 -1", true),
            ("pprof {\n}", false),
            ("pprof /foo", true),
            ("pprof {\n a b\n}", true),
            ("pprof { block\n}", false),
            ("pprof :1234 {\n block 20\n}", false),
            ("pprof {\n block 20 30\n}", true),
            ("pprof {\n block invalid\n}", true),
            ("pprof {\n unknown_property\n}", true),
            ("pprof\npprof", true),
        ];
        for (i, (input, should_err)) in tests.into_iter().enumerate() {
            assert_eq!(!setup_ok(&Setup, input), should_err, "test {i}: {input}");
        }
        assert_eq!(
            setup_err(&Setup, "pprof /foo"),
            "plugin/pprof: Corefile:2 - Error during parsing: address /foo: missing port in address"
        );
        assert_eq!(
            setup_err(&Setup, "pprof {\n block invalid\n}"),
            "plugin/pprof: Corefile:3 - Error during parsing: property 'block' invalid integer value 'invalid'"
        );
        let cfg = with_controller(NAME, "pprof :1234 {\n block 20\n}", |c| parse(c).unwrap());
        assert_eq!(
            cfg,
            Config {
                addr: ":1234".into(),
                rate_block: 20
            }
        );
    }

    async fn body(r: Response<Full<Bytes>>) -> (u16, Vec<u8>) {
        use http_body_util::BodyExt;
        let status = r.status().as_u16();
        (status, r.into_body().collect().await.unwrap().to_bytes().to_vec())
    }

    #[tokio::test]
    async fn routes() {
        let (status, _) = body(route("/debug/pprof", None).await).await;
        assert_eq!(status, 302);
        let (status, index) = body(route("/debug/pprof/", None).await).await;
        assert_eq!(status, 200);
        assert!(String::from_utf8(index).unwrap().contains("profile"));
        let (status, cmdline) = body(route("/debug/pprof/cmdline", None).await).await;
        assert_eq!(status, 200);
        assert!(!cmdline.is_empty());
        assert_eq!(body(route("/debug/pprof/heap", None).await).await.0, 404);
        assert_eq!(body(route("/other", None).await).await.0, 404);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cpu_profile_is_gzipped_protobuf() {
        // burn some CPU while profiling
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s2 = stop.clone();
        let burner = std::thread::spawn(move || {
            let mut x = 0u64;
            while !s2.load(std::sync::atomic::Ordering::Relaxed) {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            }
            x
        });
        let (status, gz) = body(route("/debug/pprof/profile", Some("seconds=1")).await).await;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        burner.join().unwrap();
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&gz));
        assert_eq!(&gz[..2], &[0x1f, 0x8b], "gzip");
        let mut raw = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&gz[..]), &mut raw).unwrap();
        // the first field is the sample_type (field 1, length-delimited)
        assert_eq!(raw[0], 0x0a);
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("samples") && text.contains("nanoseconds"));
    }
}
