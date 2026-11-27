//! The `kerndns` binary. Flags follow CoreDNS (`-conf`, `-dns.port`, ...);
//! both `-flag` and `--flag`, and `-flag value` and `-flag=value`, work.

use std::io::{BufRead, Read};
use std::process::ExitCode;

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
            let scheme = l.label.split("://").next().unwrap_or("dns");
            for z in &l.zones {
                let prefix = if scheme == "dns" {
                    String::new()
                } else {
                    format!("{scheme}://")
                };
                println!("{prefix}{z}:{}", l.port());
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
/// configuration stays.
async fn reload(
    inst: &mut Instance,
    text: &str,
    path: &str,
    opts: &Options,
    registry: &kerndns_core::Registry,
) -> Result<(), String> {
    match kerndns_server::load(text, path, registry, opts) {
        Ok(plan) => inst.reload(plan).await.map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// SHA-512 of the parsed Corefile (keys and directive tokens), so comment
/// and whitespace changes don't trigger a reload, like the `reload` plugin.
fn config_hash(corefile: &str, path: &str) -> Option<String> {
    use sha2::{Digest, Sha512};
    let blocks = kerndns_core::corefile::parse(corefile, path).ok()?;
    let mut h = Sha512::new();
    for b in &blocks {
        for k in &b.keys {
            h.update(k.as_bytes());
            h.update([0]);
        }
        for d in &b.directives {
            for t in &d.tokens {
                h.update(t.text.as_bytes());
                h.update([1]);
            }
        }
        h.update([2]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
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
                kerndns_core::error!(plugin = "reload", "Corefile changed but reload failed: {e}");
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
        match reload(inst, &text, path, opts, registry).await {
            Ok(()) => {
                hash = new_hash;
                kerndns_core::info!("Reloading complete");
                if let Some(h) = &hash
                    && kerndns_core::reload::interval().is_some()
                {
                    kerndns_core::info!(plugin = "reload", "Running configuration SHA512 = {h}");
                }
            }
            Err(e) => kerndns_core::error!(plugin = "reload", "Corefile changed but reload failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Flags, String> {
        parse_flags(args.iter().map(|s| s.to_string()))
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
