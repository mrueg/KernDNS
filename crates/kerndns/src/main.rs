//! The `kerndns` binary. Flags follow CoreDNS (`-conf`, `-dns.port`, ...);
//! both `-flag` and `--flag`, and `-flag value` and `-flag=value`, work.

use std::io::{BufRead, Read};
use std::process::ExitCode;

use kerndns_plugins::pluginmetrics as pm;
use kerndns_server::{Instance, Options};

const USAGE: &str = "Usage of kerndns:
  -bridge string
        Go bridge library with CoreDNS plugins (default $KERNDNS_BRIDGE)
  -bridge.prefer string
        Comma-separated plugins to run in Go even if a Rust port exists
        (default $KERNDNS_BRIDGE_PREFER)
  -bridge.sync string
        Comma-separated Go plugins to run on the calling thread (faster; for
        plugins that don't wait on the network)
  -conf string
        Corefile to load (default \"Corefile\"), \"stdin\" reads it from standard input
  -dns.port string
        Default port (default \"53\")
  -pidfile string
        Path to write pid file
  -plugins
        List installed plugins
  -quiet
        Quiet mode (no initialization output)
  -version
        Show version
  -report-listeners
        Print one 'KERNDNS_LISTENER <label> udp=<addr> tcp=<addr>' line per server (an
        address is empty if the listener has no such socket) and
        'KERNDNS_READY' on stdout once serving, plus 'KERNDNS_METRICS <addr>' per metrics
        endpoint (used by the CoreDNS compatibility tests)
  -control
        Read Corefiles from standard input, each one preceded by a line
        'KERNDNS_COREFILE <bytes>': the first is the configuration to start
        with, every later one is loaded in place like a reload. With
        -report-listeners, a reload reports the listener lines and
        'KERNDNS_READY' again, or 'KERNDNS_RELOAD_FAILED <error>' (used by the
        CoreDNS compatibility tests for caddy's Instance.Restart)";

#[derive(Debug, Default)]
struct Flags {
    bridge: Option<String>,
    bridge_prefer: Vec<String>,
    bridge_sync: Vec<String>,
    conf: Option<String>,
    dns_port: Option<String>,
    pidfile: Option<String>,
    plugins: bool,
    quiet: bool,
    version: bool,
    report_listeners: bool,
    control: bool,
}

fn parse_flags(args: impl IntoIterator<Item = String>) -> Result<Flags, String> {
    let mut f = Flags::default();
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        let Some(stripped) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')) else {
            return Err(format!("unexpected argument: {arg}"));
        };
        let (name, inline) = match stripped.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (stripped, None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            match inline.clone() {
                Some(v) => Ok(v),
                None => it.next().ok_or_else(|| format!("flag needs an argument: -{name}")),
            }
        };
        let boolean = |v: &Option<String>| v.as_deref().map(|s| s == "true" || s == "1").unwrap_or(true);
        match name {
            "conf" => f.conf = Some(value(name)?),
            "bridge" => f.bridge = Some(value(name)?),
            "bridge.sync" => {
                f.bridge_sync = value(name)?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            "bridge.prefer" => {
                f.bridge_prefer = value(name)?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            "dns.port" => f.dns_port = Some(value(name)?),
            "pidfile" => f.pidfile = Some(value(name)?),
            "plugins" => f.plugins = boolean(&inline),
            "quiet" => f.quiet = boolean(&inline),
            "version" => f.version = boolean(&inline),
            "report-listeners" => f.report_listeners = boolean(&inline),
            "control" => f.control = boolean(&inline),
            "h" | "help" => return Err(String::new()),
            other => return Err(format!("flag provided but not defined: -{other}")),
        }
    }
    Ok(f)
}

fn version_string() -> String {
    format!(
        "KernDNS-{}\n{}/{}, hickory-dns 0.26",
        kerndns_core::VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// Header of a Corefile frame on standard input with `-control`.
const FRAME_HEADER: &str = "KERNDNS_COREFILE ";

/// The next `-control` Corefile from `r`, or `None` at end of input.
fn read_frame(r: &mut impl BufRead) -> Result<Option<String>, String> {
    let mut header = String::new();
    if r.read_line(&mut header)
        .map_err(|e| format!("reading Corefile from stdin: {e}"))?
        == 0
    {
        return Ok(None);
    }
    let len: usize = header
        .trim_end()
        .strip_prefix(FRAME_HEADER)
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| format!("bad Corefile header on stdin: {:?}", header.trim_end()))?;
    let mut buf = vec![0; len];
    r.read_exact(&mut buf)
        .map_err(|e| format!("reading Corefile from stdin: {e}"))?;
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| "Corefile on stdin is not UTF-8".to_string())
}

fn read_corefile(flags: &Flags, port: &str) -> Result<(String, String), String> {
    if flags.control {
        return match read_frame(&mut std::io::stdin().lock())? {
            Some(s) => Ok((s, "stdin".into())),
            None => Err("no Corefile on stdin".into()),
        };
    }
    match flags.conf.as_deref() {
        Some("stdin") => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| format!("reading Corefile from stdin: {e}"))?;
            Ok((s, "stdin".into()))
        }
        Some(path) => std::fs::read_to_string(path)
            .map(|s| (s, path.to_string()))
            .map_err(|e| format!("unable to read Corefile {path}: {e}")),
        None => match std::fs::read_to_string("Corefile") {
            Ok(s) => Ok((s, "Corefile".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok((kerndns_server::config::default_corefile(port), "Corefile".into()))
            }
            Err(e) => Err(format!("unable to read Corefile: {e}")),
        },
    }
}

fn main() -> ExitCode {
    let flags = match parse_flags(std::env::args().skip(1)) {
        Ok(f) => f,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("{e}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    if flags.version {
        println!("{}", version_string());
        return ExitCode::SUCCESS;
    }
    let mut registry = kerndns_plugins::registry();
    registry.register(kerndns_kubernetes::Setup);
    registry.register(kerndns_kubernetes::external::Setup);
    if let Some(path) = flags
        .bridge
        .clone()
        .or_else(|| std::env::var("KERNDNS_BRIDGE").ok().filter(|s| !s.is_empty()))
    {
        match kerndns_go_bridge::Bridge::load(std::path::Path::new(&path)) {
            Ok(b) => {
                kerndns_go_bridge::set_sync(flags.bridge_sync.clone());
                let prefer = if flags.bridge_prefer.is_empty() {
                    std::env::var("KERNDNS_BRIDGE_PREFER")
                        .unwrap_or_default()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                } else {
                    flags.bridge_prefer.clone()
                };
                b.register(&mut registry, &prefer);
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
    }
    if flags.plugins {
        println!("Server types:\n  dns\n\nCaddyfile loaders:\n  flag\n  default\n\nOther plugins:");
        let mut names = registry.names();
        names.sort();
        for n in names {
            println!("  dns.{n}");
        }
        return ExitCode::SUCCESS;
    }

    let port = flags.dns_port.clone().unwrap_or_else(|| "53".into());
    let (corefile, path) = match read_corefile(&flags, &port) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(run(flags, corefile, path, port, registry))
}

async fn run(flags: Flags, corefile: String, path: String, port: String, registry: kerndns_core::Registry) -> ExitCode {
    let opts = Options { dns_port: port };
    let mut inst = match Instance::start(&corefile, &path, &registry, &opts).await {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(pidfile) = &flags.pidfile
        && let Err(e) = std::fs::write(pidfile, format!("{}\n", std::process::id()))
    {
        eprintln!("failed to write pidfile {pidfile}: {e}");
    }

    if !flags.quiet {
        for l in inst.listeners() {
            let (scheme, addr) = l.label.split_once("://").unwrap_or(("dns", &l.label));
            // a listener on a specific address (`bind`) says so, like `startUpZones`
            let host = addr.rsplit_once(':').map_or("", |(h, _)| h);
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let on = if host.is_empty() {
                String::new()
            } else {
                format!(" on {host}")
            };
            for z in &l.zones {
                let prefix = if scheme == "dns" {
                    String::new()
                } else {
                    format!("{scheme}://")
                };
                println!("{prefix}{z}:{}{on}", l.port());
            }
        }
        println!("{}", version_string());
    }
    if flags.report_listeners {
        report_listeners(&inst);
    }

    // -control: every later Corefile on stdin is a reload
    let control = flags.control.then(|| {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            loop {
                let frame = read_frame(&mut stdin);
                let last = !matches!(frame, Ok(Some(_)));
                if tx.send(frame).is_err() || last {
                    return;
                }
            }
        });
        rx
    });

    let report = flags.report_listeners;
    serve_until_shutdown(&mut inst, &corefile, &path, &opts, &registry, control, report).await;
    // caddy's ShutdownEvent comes before the shutdown callbacks
    inst.emit(kerndns_core::Event::Shutdown).await;
    inst.stop().await;
    if let Some(pidfile) = &flags.pidfile {
        let _ = std::fs::remove_file(pidfile);
    }
    ExitCode::SUCCESS
}

/// The `-report-listeners` lines for the running configuration.
fn report_listeners(inst: &Instance) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    for l in inst.listeners() {
        // one line per server, like CoreDNS's i.Servers() with multisocket
        let addr = |a: Option<std::net::SocketAddr>| a.map(|a| a.to_string()).unwrap_or_default();
        for _ in 0..l.servers {
            let _ = writeln!(
                out,
                "KERNDNS_LISTENER {} udp={} tcp={}",
                l.label,
                addr(l.udp),
                addr(l.tcp)
            );
        }
    }
    for addr in kerndns_core::metrics::listen_addrs() {
        let _ = writeln!(out, "KERNDNS_METRICS {addr}");
    }
    let _ = writeln!(out, "KERNDNS_READY");
    let _ = out.flush();
}

/// Load `text` and switch `inst` to it; on failure the running
/// configuration stays. The error reads like caddy's `Instance.Restart`'s:
/// starting the new configuration fails with `starting with listener file
/// descriptors: ...`, a restart hook of the running one with its error.
async fn reload(
    inst: &mut Instance,
    text: &str,
    path: &str,
    opts: &Options,
    registry: &kerndns_core::Registry,
) -> Result<(), String> {
    let starting = |e: &dyn std::fmt::Display| format!("starting with listener file descriptors: {e}");
    match kerndns_server::load(text, path, registry, opts) {
        Ok(plan) => inst.reload(plan).await.map_err(|e| match e {
            kerndns_server::StartError::Restart(e) => e,
            e => starting(&e),
        }),
        Err(e) => Err(starting(&e)),
    }
}

/// SHA-512 of the parsed Corefile, so comment and whitespace changes don't
/// trigger a reload. Like the `reload` plugin it hashes Go's
/// `json.Marshal` of caddy's server blocks (`[{"Keys":[...],"Tokens":
/// {"directive":[{"File":...,"Line":...,"Text":...}]}}]`), so the logged
/// hash and `coredns_reload_version_info` match CoreDNS's for the same
/// Corefile.
fn config_hash(corefile: &str, path: &str) -> Option<String> {
    use sha2::{Digest, Sha512};
    let blocks = kerndns_core::corefile::parse(corefile, path).ok()?;
    let json = caddy_json(&blocks, path);
    Some(
        Sha512::digest(json.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

/// `json.Marshal([]caddyfile.ServerBlock)` of the parsed Corefile `path`.
fn caddy_json(blocks: &[kerndns_core::corefile::ServerBlock], path: &str) -> String {
    use std::collections::BTreeMap;
    // the file caddy records for a token: none for the Corefile itself
    // (its lexer doesn't set one), the absolute path for imported files,
    // and for snippet tokens that of the file the snippet is in
    let file_of = |label: &str| -> String {
        let f = label.split(" (snippet ").next().unwrap_or(label);
        if f == path {
            String::new()
        } else {
            std::path::absolute(f).map_or_else(|_| f.to_string(), |p| p.display().to_string())
        }
    };
    let mut out = String::from("[");
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"Keys\":[");
        for (j, k) in b.keys.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            go_json_string(&mut out, k);
        }
        out.push_str("],\"Tokens\":{");
        let mut by_dir: BTreeMap<&str, Vec<&kerndns_core::corefile::Token>> = BTreeMap::new();
        for d in &b.directives {
            by_dir.entry(d.name.as_str()).or_default().extend(d.tokens.iter());
        }
        for (j, (name, toks)) in by_dir.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            go_json_string(&mut out, name);
            out.push_str(":[");
            for (n, t) in toks.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                out.push_str("{\"File\":");
                go_json_string(&mut out, &file_of(&t.file));
                out.push_str(&format!(",\"Line\":{},\"Text\":", t.line));
                go_json_string(&mut out, &t.text);
                out.push('}');
            }
            out.push(']');
        }
        out.push_str("}}");
    }
    out.push(']');
    out
}

/// A JSON string the way Go's `encoding/json` writes it (HTML characters
/// and U+2028/U+2029 escaped).
fn go_json_string(out: &mut String, s: &str) {
    use std::fmt::Write as _;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Serve until SIGTERM/SIGINT, reloading on SIGUSR1 and, with the `reload`
/// plugin, when the Corefile's content changes.
async fn serve_until_shutdown(
    inst: &mut Instance,
    corefile: &str,
    path: &str,
    opts: &Options,
    registry: &kerndns_core::Registry,
    mut control: Option<tokio::sync::mpsc::UnboundedReceiver<Result<Option<String>, String>>>,
    report: bool,
) {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
    let mut usr1 = signal(SignalKind::user_defined1()).expect("SIGUSR1 handler");
    let reloadable = path != "stdin";
    let mut hash = config_hash(corefile, path);
    if kerndns_core::reload::interval().is_some()
        && let Some(h) = &hash
    {
        kerndns_core::info!(plugin = "reload", "Running configuration SHA512 = {h}");
    }

    loop {
        let interval = kerndns_core::reload::interval().filter(|_| reloadable);
        let tick = async {
            match interval {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending::<()>().await,
            }
        };
        let next_control = async {
            match control.as_mut() {
                Some(rx) => rx.recv().await,
                None => std::future::pending().await,
            }
        };
        let force = tokio::select! {
            _ = term.recv() => {
                kerndns_core::info!("SIGTERM: Shutting down servers then terminating");
                return;
            }
            _ = int.recv() => {
                kerndns_core::info!("SIGINT: Shutting down servers then terminating");
                return;
            }
            _ = usr1.recv() => {
                kerndns_core::info!("SIGUSR1: Reloading");
                true
            }
            _ = tick => false,
            frame = next_control => {
                match frame {
                    Some(Ok(Some(text))) => {
                        // like caddy's Instance.Restart: always load, even if unchanged
                        kerndns_core::info!("Reloading");
                        match reload(inst, &text, path, opts, registry).await {
                            Ok(()) => {
                                kerndns_core::info!("Reloading complete");
                                if report {
                                    report_listeners(inst);
                                }
                            }
                            Err(e) => {
                                kerndns_core::error!("Restart failed: {e}");
                                if report {
                                    println!("KERNDNS_RELOAD_FAILED {}", e.replace('\n', " "));
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        kerndns_core::error!("{e}");
                        control = None;
                    }
                    Some(Ok(None)) | None => control = None,
                }
                continue;
            }
        };
        if !reloadable {
            kerndns_core::warning!("cannot reload a Corefile read from stdin");
            continue;
        }
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                // the reload plugin skips a Corefile it can't load
                if force {
                    kerndns_core::error!("SIGUSR1: loading updated Caddyfile: unable to read Corefile {path}: {e}");
                }
                continue;
            }
        };
        let new_hash = config_hash(&text, path);
        if !force && (new_hash.is_none() || new_hash == hash) {
            if new_hash.is_none() {
                kerndns_core::warning!(plugin = "reload", "Corefile parse failed");
            }
            continue;
        }
        // like the reload plugin: don't retry the same file, even if it fails
        let changed = !force && new_hash != hash;
        if changed {
            if let Some(old) = &hash {
                let _ = pm::RELOAD_INFO.remove_label_values(&["sha512", old]);
            }
            hash = new_hash.clone();
        }
        // caddy's Instance.Restart logs this
        kerndns_core::info!("Reloading");
        let res = reload(inst, &text, path, opts, registry).await;
        if changed && let Some(h) = &new_hash {
            pm::RELOAD_INFO.with_label_values(&["sha512", h]).set(1.0);
        }
        match res {
            Ok(()) => {
                if force {
                    hash = new_hash;
                }
                // the new instance's startup logs its hash, then caddy says it's done
                if let Some(h) = &hash
                    && kerndns_core::reload::interval().is_some()
                {
                    kerndns_core::info!(plugin = "reload", "Running configuration SHA512 = {h}");
                }
                kerndns_core::info!("Reloading complete");
            }
            Err(e) => {
                // the old configuration still serves (Instance.Restart logs
                // this after its restart-failed hooks), then the caller
                kerndns_core::error!("Restart failed: {e}");
                if force {
                    kerndns_core::error!("SIGUSR1: {e}");
                } else {
                    pm::RELOAD_FAILED.inc();
                    kerndns_core::error!(plugin = "reload", "Corefile changed but reload failed: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Flags, String> {
        parse_flags(args.iter().map(|s| s.to_string()))
    }

    /// The JSON CoreDNS's `reload` hashes, as Go's `json.Marshal` of
    /// caddy's server blocks writes it for the same Corefile (checked with
    /// caddy v1.1.4): no file for the Corefile's own tokens and snippets
    /// defined in it, the absolute path for imported files, directives
    /// sorted by name, HTML characters escaped.
    #[test]
    fn reload_hash_input_matches_caddy() {
        let dir = std::env::temp_dir().join(format!("kerndns-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("extra.conf"), "whoami\n").unwrap();
        let corefile = "(snip) {\n    log\n}\nexample.org:1053 example.net:1053 {\n    reload 2s\n    import snip\n    whoami\n    template IN TXT example.org {\n        answer \"{{ .Name }} 60 IN TXT \\\"a<b>&c\\\"\"\n    }\n    errors\n}\n.:1053 {\n    import extra.conf\n    reload\n}\n";
        let path = dir.join("Corefile").display().to_string();
        let blocks = kerndns_core::corefile::parse(corefile, &path).unwrap();
        let extra = dir.join("extra.conf").display().to_string();
        let want = format!(
            r#"[{{"Keys":["example.org:1053","example.net:1053"],"Tokens":{{"errors":[{{"File":"","Line":11,"Text":"errors"}}],"log":[{{"File":"","Line":2,"Text":"log"}}],"reload":[{{"File":"","Line":5,"Text":"reload"}},{{"File":"","Line":5,"Text":"2s"}}],"template":[{{"File":"","Line":8,"Text":"template"}},{{"File":"","Line":8,"Text":"IN"}},{{"File":"","Line":8,"Text":"TXT"}},{{"File":"","Line":8,"Text":"example.org"}},{{"File":"","Line":8,"Text":"{{"}},{{"File":"","Line":9,"Text":"answer"}},{{"File":"","Line":9,"Text":"{{{{ .Name }}}} 60 IN TXT \"a\u003cb\u003e\u0026c\""}},{{"File":"","Line":10,"Text":"}}"}}],"whoami":[{{"File":"","Line":7,"Text":"whoami"}}]}}}},{{"Keys":[".:1053"],"Tokens":{{"reload":[{{"File":"","Line":15,"Text":"reload"}}],"whoami":[{{"File":"{extra}","Line":1,"Text":"whoami"}}]}}}}]"#
        );
        assert_eq!(caddy_json(&blocks, &path), want);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn flags() {
        let f = p(&["-conf", "x", "--dns.port=1053", "-quiet"]).unwrap();
        assert_eq!(f.conf.as_deref(), Some("x"));
        assert_eq!(f.dns_port.as_deref(), Some("1053"));
        assert!(f.quiet);
        assert!(p(&["-nope"]).is_err());
        assert!(p(&["-conf"]).is_err());
        assert!(!p(&["-quiet=false"]).unwrap().quiet);
        assert!(p(&["-control"]).unwrap().control);
    }

    #[test]
    fn frames() {
        let mut r = std::io::Cursor::new(b"KERNDNS_COREFILE 5\n.:53\nKERNDNS_COREFILE 0\n".to_vec());
        assert_eq!(read_frame(&mut r).unwrap().as_deref(), Some(".:53\n"));
        assert_eq!(read_frame(&mut r).unwrap().as_deref(), Some(""));
        assert_eq!(read_frame(&mut r).unwrap(), None);
        let mut bad = std::io::Cursor::new(b"hello\n".to_vec());
        assert!(read_frame(&mut bad).is_err());
        let mut short = std::io::Cursor::new(b"KERNDNS_COREFILE 9\nabc".to_vec());
        assert!(read_frame(&mut short).is_err());
    }
}
