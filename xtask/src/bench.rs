//! `cargo xtask bench`: CoreDNS vs KernDNS with dnsperf.
//!
//! Scenarios live in `bench/`:
//!
//! - level 2, one directory per plugin: `bench/plugins/<plugin>/`
//! - level 3, common setups: `bench/setups/<name>/`
//!
//! A directory holds one or more cases: `Corefile` (named after the
//! directory) and `<case>.Corefile` (named `<dir>/<case>`), plus fixtures
//! and query files. A case is a Corefile template whose leading comments
//! describe it:
//!
//! ```text
//! # about: what the case measures
//! # queries: {FIX}/q-file.txt       (dnsperf input; default {DIR}/queries.txt)
//! # dnsperf: -m dot                 (extra dnsperf arguments; -m doq, doh3
//!                                    or grpc run `cargo xtask loadgen`)
//! # needs: kubernetes               (start the fake Kubernetes API server)
//! # live-queries: {DIR}/q-live.txt  (dnsperf input with --kubeconfig)
//! # needs: etcd                     (start a throwaway etcd with SkyDNS records)
//! # bridge: etcd                    (KernDNS runs these plugins in Go, -bridge)
//! ```
//!
//! Placeholders: `{PORT}` (the server's port), `{DIR}` (the case's
//! directory), `{BENCH}` (`bench/`), `{FIX}` (generated fixtures: zones of
//! 100, 10k and 100k names, a hosts file and query files), `{BACKEND}`,
//! `{BACKEND_DOT}` and `{BACKEND_GRPC}` (a shared upstream, CoreDNS serving
//! the 10k zone over UDP/TCP, DoT and gRPC, with transfers allowed),
//! `{DNSTAP}` (a unix socket where the harness accepts dnstap Frame
//! Streams and counts the messages), `{KUBECONFIG}` (the fake API
//! server, 1000 Services; with `--kubeconfig PATH`, that file instead, for
//! a live cluster) and `{ETCD}` (the etcd client port; its queries are
//! `{FIX}/q-etcd.txt`). `bench/plugins/EXEMPT` lists plugins without a
//! scenario and why; `--check` fails for any other plugin in KernDNS's
//! registry that has none.
//!
//! Both servers get the same Corefile and fixtures and are pinned to the
//! same CPUs; dnsperf and the backend run on other CPUs. For every case and
//! server: max QPS (dnsperf with many outstanding queries), then latency at
//! a fixed rate (half of CoreDNS's max QPS), CPU time per query and peak
//! RSS. Level 2 results are also reported as the added CPU time per query
//! over the `whoami` baseline, which always runs first.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::root;

/// CPU sets for the servers under test, dnsperf and the shared backend.
struct Cpus {
    server: String,
    dnsperf: String,
    backend: String,
}

/// With 8 CPUs (the 4-core/8-thread laptop the numbers in the README come
/// from), the servers get two cores with their hyperthreads, and dnsperf and
/// the backend one core each. With fewer CPUs, half go to the servers.
fn cpus() -> Cpus {
    let n = std::thread::available_parallelism().map_or(1, |n| n.get());
    if n >= 8 {
        Cpus {
            server: "0,1,4,5".into(),
            dnsperf: "2,6".into(),
            backend: "3,7".into(),
        }
    } else if n >= 2 {
        let half = n / 2;
        let rest = format!("{half}-{}", n - 1);
        Cpus {
            server: format!("0-{}", half - 1),
            dnsperf: rest.clone(),
            backend: rest,
        }
    } else {
        Cpus {
            server: "0".into(),
            dnsperf: "0".into(),
            backend: "0".into(),
        }
    }
}

/// One benchmark case: a Corefile template and how to drive it.
#[derive(Debug, Clone)]
struct Case {
    /// `cache`, `cache/miss`, `resolver`.
    name: String,
    /// 2 (per plugin) or 3 (common setups).
    level: u8,
    /// The directory name: the plugin for level 2.
    group: String,
    dir: PathBuf,
    path: PathBuf,
    about: String,
    queries: String,
    /// `# live-queries:`, used instead of `queries` with `--kubeconfig`.
    live_queries: Option<String>,
    dnsperf: Vec<String>,
    needs_k8s: bool,
    needs_etcd: bool,
    /// Plugins KernDNS runs in Go through the bridge.
    bridge: Vec<String>,
    corefile: String,
}

const PLACEHOLDERS: &[&str] = &[
    "PORT",
    "DIR",
    "BENCH",
    "FIX",
    "BACKEND",
    "BACKEND_DOT",
    "BACKEND_GRPC",
    "DNSTAP",
    "KUBECONFIG",
    "ETCD",
];

fn parse_case(level: u8, group: &str, dir: &Path, path: &Path) -> Result<Case> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let file = path.file_name().unwrap().to_string_lossy();
    let name = match file.strip_suffix(".Corefile") {
        Some(case) => format!("{group}/{case}"),
        None => group.to_string(),
    };
    let mut case = Case {
        name,
        level,
        group: group.to_string(),
        dir: dir.to_path_buf(),
        path: path.to_path_buf(),
        about: String::new(),
        queries: "{DIR}/queries.txt".into(),
        live_queries: None,
        dnsperf: Vec::new(),
        needs_k8s: false,
        needs_etcd: false,
        bridge: Vec::new(),
        corefile: text.clone(),
    };
    for line in text.lines() {
        let Some(c) = line.strip_prefix('#') else { break };
        let Some((key, value)) = c.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "about" => case.about = value.to_string(),
            "queries" => case.queries = value.to_string(),
            "live-queries" => case.live_queries = Some(value.to_string()),
            "dnsperf" => case.dnsperf = value.split_whitespace().map(String::from).collect(),
            "bridge" => case.bridge = split_list(value),
            "needs" => match value {
                "kubernetes" => case.needs_k8s = true,
                "etcd" => case.needs_etcd = true,
                other => bail!("{}: unknown need {other:?}", path.display()),
            },
            other => bail!("{}: unknown header {other:?}", path.display()),
        }
    }
    if case.about.is_empty() {
        bail!("{}: missing \"# about:\" header", path.display());
    }
    Ok(case)
}

/// The case files of one directory: `Corefile` first, then `*.Corefile`.
fn case_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    v.retain(|p| {
        let f = p.file_name().unwrap().to_string_lossy();
        f == "Corefile" || f.ends_with(".Corefile")
    });
    v.sort_by_key(|p| (p.file_name().unwrap() != "Corefile", p.clone()));
    Ok(v)
}

fn subdirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let p = e?.path();
        if p.is_dir() {
            v.push(p);
        }
    }
    v.sort();
    Ok(v)
}

/// All cases: level 2 (whoami first), then level 3.
fn discover(bench: &Path) -> Result<Vec<Case>> {
    let mut cases = Vec::new();
    for (level, sub) in [(2u8, "plugins"), (3, "setups")] {
        for dir in subdirs(&bench.join(sub))? {
            let group = dir.file_name().unwrap().to_string_lossy().to_string();
            for f in case_files(&dir)? {
                cases.push(parse_case(level, &group, &dir, &f)?);
            }
        }
    }
    cases.sort_by_key(|c| (c.level, c.group != "whoami"));
    Ok(cases)
}

/// `bench/plugins/EXEMPT`: plugin -> reason.
fn exemptions(bench: &Path) -> Result<BTreeMap<String, String>> {
    let path = bench.join("plugins/EXEMPT");
    let mut m = BTreeMap::new();
    for (i, line) in fs::read_to_string(&path)?.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, reason)) = line.split_once(':').filter(|(_, r)| !r.trim().is_empty()) else {
            bail!("{}:{}: expected \"plugin: reason\"", path.display(), i + 1);
        };
        m.insert(name.trim().to_string(), reason.trim().to_string());
    }
    Ok(m)
}

/// Every plugin KernDNS registers (the binary adds kubernetes and
/// k8s_external to the plugins crate's registry).
fn registered_plugins() -> BTreeSet<String> {
    let mut r = kerndns_plugins::registry();
    r.register(kerndns_kubernetes::Setup);
    r.register(kerndns_kubernetes::external::Setup);
    r.names().into_iter().map(String::from).collect()
}

fn render(text: &str, vars: &BTreeMap<&str, String>) -> String {
    let mut s = text.to_string();
    for (k, v) in vars {
        s = s.replace(&format!("{{{k}}}"), v);
    }
    s
}

/// `{NAME}` placeholders (upper case only, so templates' `{{ .Name }}` and
/// rewrite's `{1}` don't count).
fn placeholders(text: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find('{') {
        rest = &rest[i + 1..];
        let end = rest.find('}').unwrap_or(0);
        let name = &rest[..end];
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            v.push(name.to_string());
        }
    }
    v
}

/// `cargo xtask bench --check`: every registered plugin has a level 2
/// scenario directory or an exemption, and every case is well-formed.
fn check(bench: &Path) -> Result<()> {
    let registered = registered_plugins();
    let exempt = exemptions(bench)?;
    let cases = discover(bench)?;
    let mut problems = Vec::new();
    let dirs: BTreeSet<String> = subdirs(&bench.join("plugins"))?
        .iter()
        .map(|d| d.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    for p in &registered {
        match (dirs.contains(p), exempt.contains_key(p)) {
            (false, false) => problems.push(format!(
                "plugin {p} has no scenario: add bench/plugins/{p}/Corefile (or an entry in bench/plugins/EXEMPT)"
            )),
            (true, true) => problems.push(format!("plugin {p} has a scenario and an exemption")),
            _ => {}
        }
    }
    for d in &dirs {
        if !registered.contains(d) {
            problems.push(format!("bench/plugins/{d}: no plugin {d} is registered"));
        }
        if !cases.iter().any(|c| c.level == 2 && &c.group == d) {
            problems.push(format!("bench/plugins/{d}: no Corefile"));
        }
    }
    for p in exempt.keys() {
        if !registered.contains(p) {
            problems.push(format!("bench/plugins/EXEMPT: no plugin {p} is registered"));
        }
    }
    let mut vars = BTreeMap::new();
    for k in PLACEHOLDERS {
        vars.insert(*k, "1053".to_string());
    }
    vars.insert("BENCH", bench.display().to_string());
    for c in &cases {
        let rel = c.path.strip_prefix(bench).unwrap_or(&c.path).display().to_string();
        let queries = std::iter::once(&c.queries).chain(&c.live_queries);
        for ph in placeholders(&c.corefile)
            .into_iter()
            .chain(queries.clone().flat_map(|q| placeholders(q)))
        {
            if !PLACEHOLDERS.contains(&ph.as_str()) {
                problems.push(format!("{rel}: unknown placeholder {{{ph}}}"));
            }
        }
        for q in queries.filter(|q| !q.starts_with("{FIX}")) {
            let mut v = vars.clone();
            v.insert("DIR", c.dir.display().to_string());
            let q = render(q, &v);
            if !Path::new(&q).is_file() {
                problems.push(format!("{rel}: query file {q} does not exist"));
            }
        }
        let mut v = vars.clone();
        v.insert("DIR", c.dir.display().to_string());
        match kerndns_corefile::parse(&render(&c.corefile, &v), &c.path.display().to_string()) {
            Err(e) => problems.push(format!("{rel}: {e}")),
            Ok(blocks) => {
                let used: BTreeSet<&str> = blocks
                    .iter()
                    .flat_map(|b| b.directives.iter().map(|d| d.name.as_str()))
                    .collect();
                for u in &used {
                    if c.bridge.iter().any(|b| b == u) {
                        if !bridge_plugins().contains(u) {
                            problems.push(format!(
                                "{rel}: plugin {u} is not in the bridge the benchmarks build ({})",
                                crate::DEFAULT_BRIDGE_PLUGINS
                            ));
                        }
                    } else if !registered.contains(*u) {
                        problems.push(format!("{rel}: plugin {u} is not registered"));
                    }
                }
                if c.level == 2 && !used.contains(c.group.as_str()) {
                    problems.push(format!("{rel}: does not use the {} plugin", c.group));
                }
            }
        }
    }
    let covered = registered.iter().filter(|p| dirs.contains(*p)).count();
    println!(
        "{} plugins registered: {covered} with a level 2 scenario ({} cases), {} exempt; {} level 3 setups",
        registered.len(),
        cases.iter().filter(|c| c.level == 2).count(),
        exempt.len(),
        cases.iter().filter(|c| c.level == 3).count()
    );
    if !problems.is_empty() {
        for p in &problems {
            eprintln!("  {p}");
        }
        bail!("bench check failed: {} problem(s)", problems.len());
    }
    Ok(())
}

fn zone(n: u32) -> Result<String> {
    let mut z = String::from(
        "$ORIGIN example.org.\n$TTL 3600\n@ IN SOA ns1 hostmaster 2024010101 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.53\n*.wild IN A 192.0.2.99\n",
    );
    for i in 0..n {
        writeln!(z, "www{i} IN A 10.{}.{}.{}", i >> 16 & 255, i >> 8 & 255, i & 255)?;
        if i % 4 == 0 {
            writeln!(z, "www{i} IN AAAA fd00::{:x}:{:x}", i >> 16, i & 0xffff)?;
        }
        if i % 10 == 0 {
            writeln!(z, "alias{i} IN CNAME www{i}")?;
        }
    }
    Ok(z)
}

/// Queries for a zone of `n` names: hits, AAAA, NXDOMAIN, wildcard, CNAME.
fn zone_queries(n: u32, count: u32) -> Result<String> {
    let mut s = String::new();
    for i in 0..count {
        let k = (i * 7) % n;
        match i % 8 {
            0..=3 => writeln!(s, "www{k}.example.org A")?,
            4 => writeln!(s, "www{k}.example.org AAAA")?,
            5 => writeln!(s, "nx{k}.example.org A")?,
            6 => writeln!(s, "x{k}.wild.example.org A")?,
            _ => writeln!(s, "alias{}.example.org A", k / 10 * 10)?,
        }
    }
    Ok(s)
}

const K8S_SERVICES: usize = 1000;
const K8S_NAMESPACES: usize = 10;

fn write_fixtures(dir: &Path) -> Result<()> {
    fs::write(dir.join("db.example.org"), zone(10_000)?)?;
    fs::write(dir.join("db.100k.example.org"), zone(100_000)?)?;
    fs::write(dir.join("db.100.example.org"), zone(100)?)?;
    fs::write(dir.join("q-file.txt"), zone_queries(10_000, 4000)?)?;
    fs::write(dir.join("q-file-100k.txt"), zone_queries(100_000, 40_000)?)?;
    fs::write(dir.join("q-file-100.txt"), zone_queries(100, 400)?)?;

    let mut h = String::new();
    for i in 0..10000u32 {
        writeln!(h, "10.{}.{}.{} h{i}.hosts.example", i / 250, i / 250, i % 250 + 1)?;
        writeln!(h, "fd00::{i:x} h{i}.hosts.example")?;
    }
    fs::write(dir.join("hosts"), h)?;
    let mut s = String::new();
    for i in 0..3000u32 {
        let n = i * 3;
        match i % 3 {
            0 => writeln!(s, "h{n}.hosts.example A")?,
            1 => writeln!(s, "h{n}.hosts.example AAAA")?,
            _ => writeln!(s, "{}.{}.10.in-addr.arpa PTR", n % 250 + 1, n / 250)?,
        }
    }
    fs::write(dir.join("q-hosts.txt"), s)?;

    let s: String = (0..1000).map(|i| format!("host{i}.example.org A\n")).collect();
    fs::write(dir.join("q-example.txt"), s)?;

    // kubernetes: service A, SRV, PTR and a search-path NXDOMAIN
    let mut s = String::new();
    let mut ext = String::new();
    for i in 0..2000 {
        let k = (i * 7919) % K8S_SERVICES;
        let ns = k % K8S_NAMESPACES;
        match i % 4 {
            0 => writeln!(s, "svc-{k}.ns-{ns}.svc.cluster.local A")?,
            1 => writeln!(s, "_http._tcp.svc-{k}.ns-{ns}.svc.cluster.local SRV")?,
            2 => writeln!(s, "{}.{}.96.10.in-addr.arpa PTR", k & 255, (k >> 8) & 255)?,
            _ => writeln!(s, "svc-{k}.ns-{ns}.svc.cluster.local.ns-{ns}.svc.cluster.local A")?,
        }
        if i % 2 == 0 {
            writeln!(ext, "svc-{k}.ns-{ns}.example.com A")?;
        } else {
            writeln!(ext, "nx-{k}.ns-{ns}.example.com A")?;
        }
    }
    fs::write(dir.join("q-k8s.txt"), s)?;
    fs::write(dir.join("q-k8s-external.txt"), ext)?;
    Ok(())
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> Result<u16> {
    // a port free for both UDP and TCP
    loop {
        let u = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = u.local_addr()?.port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
}

/// How to tell that a server is up.
#[derive(Debug, Clone, Copy)]
enum Probe {
    /// It answers a query over UDP.
    Udp,
    /// It accepts a TCP connection (TLS, HTTPS and gRPC listeners).
    Tcp,
    /// It answers a query over QUIC (DoQ, DoH3).
    Quic(crate::loadgen::Mode),
}

impl Probe {
    /// From a case's extra dnsperf arguments (`-m MODE`).
    fn for_args(args: &[String]) -> Probe {
        match loadgen_mode(args) {
            Some(m @ (crate::loadgen::Mode::Doq | crate::loadgen::Mode::Doh3)) => Probe::Quic(m),
            Some(crate::loadgen::Mode::Grpc) => Probe::Tcp,
            None if args
                .windows(2)
                .any(|w| w[0] == "-m" && matches!(w[1].as_str(), "dot" | "doh")) =>
            {
                Probe::Tcp
            }
            None => Probe::Udp,
        }
    }
}

/// An optimized xtask binary for `loadgen` (bench itself may be a debug
/// build), built by `run` when a selected case needs it.
static LOADGEN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// `-m doq|doh3|grpc`: modes dnsperf lacks, run with `cargo xtask loadgen`.
fn loadgen_mode(args: &[String]) -> Option<crate::loadgen::Mode> {
    args.windows(2)
        .find(|w| w[0] == "-m")
        .and_then(|w| crate::loadgen::Mode::parse(&w[1]))
}

/// Waits until the server answers on `port` (see [`Probe`]).
fn wait_up(port: u16, child: &mut Child, probe: Probe) -> Result<()> {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let q = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 1];
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            bail!("server exited during startup");
        }
        match probe {
            Probe::Udp => {}
            Probe::Tcp => {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Probe::Quic(mode) => {
                if crate::loadgen::probe(mode, port) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
        }
        let _ = sock.send_to(&q, ("127.0.0.1", port));
        let mut b = [0u8; 512];
        if sock.recv_from(&mut b).is_ok() {
            return Ok(());
        }
    }
    bail!("server did not start on port {port}")
}

fn start(bin: &Path, args: &[String], corefile: &Path, port: u16, cpus: &str, probe: Probe) -> Result<Proc> {
    let log = corefile.with_extension("log");
    let mut child = Command::new("taskset")
        .args(["-c", cpus])
        .arg(bin)
        .args(args)
        .arg("-conf")
        .arg(corefile)
        .arg("-quiet")
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log)?)
        .spawn()
        .with_context(|| format!("starting {}", bin.display()))?;
    if let Err(e) = wait_up(port, &mut child, probe) {
        let _ = child.kill();
        let out = fs::read_to_string(&log).unwrap_or_default();
        bail!("{e}: {}\n{}", bin.display(), out.trim());
    }
    Ok(Proc(child))
}

/// utime + stime in seconds, and peak RSS in MiB.
fn proc_usage(pid: u32) -> (f64, f64) {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let after = stat.rsplit(')').next().unwrap_or("");
    let f: Vec<&str> = after.split_whitespace().collect();
    let ticks = f.get(11).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0)
        + f.get(12).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let hwm = status
        .lines()
        .find(|l| l.starts_with("VmHWM"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    (ticks / 100.0, hwm / 1024.0)
}

#[derive(Debug, Default, Clone)]
struct Run {
    qps: f64,
    sent: f64,
    lost: f64,
    avg_us: f64,
    stddev_us: f64,
    max_us: f64,
    /// Response codes with their share in percent.
    rcodes: Vec<(String, f64)>,
}

impl Run {
    fn rcodes(&self) -> String {
        self.rcodes
            .iter()
            .map(|(c, p)| format!("{c} {p:.0}%"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// dnsperf's `Response codes:` line: `NOERROR 900 (90.00%), NXDOMAIN 100 (10.00%)`.
fn parse_rcodes(text: &str) -> Vec<(String, f64)> {
    let Some(line) = text
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("Response codes:"))
    else {
        return Vec::new();
    };
    line.split(',')
        .filter_map(|part| {
            let mut f = part.split_whitespace();
            let code = f.next()?.to_string();
            let pct = f
                .nth(1)?
                .trim_matches(|c| c == '(' || c == ')' || c == '%')
                .parse()
                .ok()?;
            Some((code, pct))
        })
        .collect()
}

fn dnsperf(cpus: &Cpus, port: u16, queries: &Path, secs: u32, rate: Option<u32>, extra: &[String]) -> Result<Run> {
    let mut cmd = Command::new("taskset");
    cmd.args(["-c", &cpus.dnsperf]);
    if loadgen_mode(extra).is_some() {
        let exe = LOADGEN.get().cloned().map_or_else(std::env::current_exe, Ok)?;
        cmd.arg(exe).arg("loadgen");
    } else {
        cmd.arg("dnsperf");
    }
    cmd.args(["-s", "127.0.0.1", "-p", &port.to_string(), "-d"])
        .arg(queries)
        .args(["-c", "32", "-T", "2", "-q", "500", "-l", &secs.to_string()])
        .args(extra)
        .env("LC_ALL", "C");
    if let Some(r) = rate {
        cmd.args(["-Q", &r.to_string()]);
    }
    let out = cmd.output().context("running dnsperf (is it installed?)")?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        bail!(
            "dnsperf failed: {}{}",
            text.trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // dnsperf -u reports "Updates ..." instead of "Queries ..."
    let num = |key: &str, idx: usize| -> f64 {
        let alt = key.replace("Queries", "Updates");
        text.lines()
            .find(|l| l.trim_start().starts_with(key) || l.trim_start().starts_with(&alt))
            .and_then(|l| l.split_whitespace().nth(idx))
            .map(|v| v.trim_matches(|c| c == '(' || c == ')' || c == ',' || c == '%'))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0)
    };
    let max_line = text
        .lines()
        .find(|l| l.trim_start().starts_with("Average Latency"))
        .unwrap_or("");
    let max = max_line
        .split("max ")
        .nth(1)
        .and_then(|v| v.trim_end_matches(')').trim().parse::<f64>().ok())
        .unwrap_or(0.0);
    Ok(Run {
        qps: num("Queries per second", 3),
        sent: num("Queries sent", 2),
        lost: num("Queries lost", 2),
        avg_us: num("Average Latency", 3) * 1e6,
        stddev_us: num("Latency StdDev", 3) * 1e6,
        max_us: max * 1e6,
        rcodes: parse_rcodes(&text),
    })
}

#[derive(Debug, Default, Clone)]
struct Result1 {
    max: Run,
    fixed: Run,
    /// CPU seconds per million queries = CPU µs per query.
    cpu_us: f64,
    rss_mib: f64,
}

/// Max QPS, then latency at `rate` (or half of this server's max), on one
/// server process. Returns the result and the rate used.
#[allow(clippy::too_many_arguments)]
fn measure(
    cpus: &Cpus,
    bin: &Path,
    args: &[String],
    corefile: &Path,
    port: u16,
    case: &Case,
    q: &Path,
    secs: u32,
    rate: Option<u32>,
) -> Result<(Result1, u32)> {
    let p = start(bin, args, corefile, port, &cpus.server, Probe::for_args(&case.dnsperf))?;
    let pid = p.0.id();
    dnsperf(cpus, port, q, 2, None, &case.dnsperf)?; // warm up (fills caches)
    let (cpu0, _) = proc_usage(pid);
    let max = dnsperf(cpus, port, q, secs, None, &case.dnsperf)?;
    let (cpu1, _) = proc_usage(pid);
    let rate = rate.unwrap_or(((max.qps / 2.0) as u32).max(1000));
    let fixed = dnsperf(cpus, port, q, secs, Some(rate), &case.dnsperf)?;
    let (_, rss) = proc_usage(pid);
    let answered = max.sent - max.lost;
    let cpu_us = if answered > 0.0 {
        (cpu1 - cpu0) / answered * 1e6
    } else {
        0.0
    };
    Ok((
        Result1 {
            max,
            fixed,
            cpu_us,
            rss_mib: rss,
        },
        rate,
    ))
}

fn build_kerndns(root: &Path) -> Result<PathBuf> {
    if !Command::new(env!("CARGO"))
        .current_dir(root)
        .args(["build", "--release", "--package", "kerndns"])
        .status()?
        .success()
    {
        bail!("building kerndns failed");
    }
    Ok(root.join("target/release/kerndns"))
}

/// A release build of xtask for `loadgen` (`cargo xtask` runs a debug
/// build, too slow to load a server).
fn build_loadgen(root: &Path) -> Result<PathBuf> {
    if !Command::new(env!("CARGO"))
        .current_dir(root)
        .args(["build", "--release", "--package", "xtask"])
        .status()?
        .success()
    {
        bail!("building the load generator failed");
    }
    Ok(root.join("target/release/xtask"))
}

/// The reference CoreDNS: `path` if given, else built from the submodule.
fn coredns(root: &Path, path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = path {
        return Ok(p);
    }
    let coredns = root.join("target/coredns-ref");
    if !Command::new("go")
        .current_dir(root.join("third_party/coredns"))
        .args(["build", "-o"])
        .arg(&coredns)
        .arg(".")
        .status()?
        .success()
    {
        bail!("building CoreDNS failed");
    }
    Ok(coredns)
}

fn split_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Whether two rcode distributions differ by more than 2 points anywhere.
fn rcodes_differ(a: &[(String, f64)], b: &[(String, f64)]) -> bool {
    let get = |v: &[(String, f64)], k: &str| v.iter().find(|(c, _)| c == k).map_or(0.0, |(_, p)| *p);
    a.iter().chain(b).any(|(k, _)| (get(a, k) - get(b, k)).abs() > 2.0)
}

pub fn run(args: &[String]) -> Result<()> {
    let mut levels: Vec<u8> = Vec::new();
    let mut plugins: Vec<String> = Vec::new();
    let mut only: Vec<String> = Vec::new();
    let mut secs = 10u32;
    let mut runs = 1usize;
    let mut coredns_bin = None;
    let mut live_kubeconfig: Option<PathBuf> = None;
    let mut do_check = false;
    let mut list = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--check" => do_check = true,
            "--list" => list = true,
            "--level" => {
                for l in split_list(it.next().context("--level needs 2 or 3")?) {
                    match l.as_str() {
                        "2" => levels.push(2),
                        "3" => levels.push(3),
                        other => bail!("--level: unknown level {other} (2: per plugin, 3: common setups)"),
                    }
                }
            }
            "--plugin" => plugins.extend(split_list(it.next().context("--plugin needs a name")?)),
            "--scenario" => only.extend(split_list(it.next().context("--scenario needs a name")?)),
            "--duration" => secs = it.next().context("--duration needs seconds")?.parse()?,
            "--runs" => runs = it.next().context("--runs needs a count")?.parse::<usize>()?.max(1),
            "--coredns" => coredns_bin = Some(PathBuf::from(it.next().context("--coredns needs a path")?)),
            "--kubeconfig" => {
                let p = PathBuf::from(it.next().context("--kubeconfig needs a path")?);
                live_kubeconfig = Some(fs::canonicalize(&p).with_context(|| format!("{}", p.display()))?);
            }
            other => bail!("unknown argument {other}"),
        }
    }

    let root = root();
    let bench = root.join("bench");
    if do_check {
        return check(&bench);
    }
    let all = discover(&bench)?;
    for p in &plugins {
        if !all.iter().any(|c| c.level == 2 && &c.group == p) {
            bail!("no scenario for plugin {p} in bench/plugins");
        }
    }
    for s in &only {
        if !all.iter().any(|c| &c.name == s) {
            bail!("no scenario {s} (see --list)");
        }
    }
    let selected = |c: &Case| {
        (levels.is_empty() || levels.contains(&c.level))
            && (plugins.is_empty() || (c.level == 2 && plugins.contains(&c.group)))
            && (only.is_empty() || only.contains(&c.name))
    };
    let mut cases: Vec<Case> = all.iter().filter(|c| selected(c)).cloned().collect();
    // level 2 costs are relative to the whoami baseline: always run it
    if cases.iter().any(|c| c.level == 2) && !cases.iter().any(|c| c.name == "whoami") {
        let base = all
            .iter()
            .find(|c| c.name == "whoami")
            .context("bench/plugins/whoami is missing")?;
        cases.insert(0, base.clone());
    }
    if list {
        for c in &cases {
            println!("level {}  {:24} {}", c.level, c.name, c.about);
        }
        return Ok(());
    }
    if cases.is_empty() {
        bail!("no scenario selected");
    }

    let cpus = cpus();
    let work = root.join("target/bench");
    let fix = work.join("fixtures");
    fs::create_dir_all(&fix)?;
    write_fixtures(&fix)?;
    let kerndns = build_kerndns(&root)?;
    if cases.iter().any(|c| loadgen_mode(&c.dnsperf).is_some()) {
        let _ = LOADGEN.set(build_loadgen(&root)?);
    }
    let coredns = coredns(&root, coredns_bin)?;

    // the shared upstream for forward and secondary: CoreDNS serving the zone
    let backend_port = free_port()?;
    let backend_dot = free_port()?;
    let backend_grpc = free_port()?;
    let tls = bench.join("shared/tls");
    let backend_cf = work.join("backend.conf");
    fs::write(
        &backend_cf,
        format!(
            "example.org:{backend_port} {{\n    file {fix}/db.example.org\n    transfer {{\n        to *\n    }}\n}}\ntls://example.org:{backend_dot} {{\n    tls {tls}/cert.pem {tls}/key.pem\n    file {fix}/db.example.org\n}}\ngrpc://example.org:{backend_grpc} {{\n    file {fix}/db.example.org\n}}\n",
            fix = fix.display(),
            tls = tls.display()
        ),
    )?;
    let _backend = start(&coredns, &[], &backend_cf, backend_port, &cpus.backend, Probe::Udp)?;

    // the Go bridge, for setups where KernDNS runs some plugins in Go
    let bridge_args = if cases.iter().any(|c| !c.bridge.is_empty()) {
        let lib = crate::build_bridge(&root, crate::DEFAULT_BRIDGE_PLUGINS, None)?;
        vec!["-bridge".to_string(), lib.display().to_string()]
    } else {
        Vec::new()
    };

    // etcd with SkyDNS records, for the etcd plugin
    let etcd_port = free_port()?;
    let _etcd = if cases.iter().any(|c| c.needs_etcd) {
        Some(start_etcd(&work, etcd_port, &cpus.backend, &fix)?)
    } else {
        None
    };

    // the fake Kubernetes API server for kubernetes and k8s_external
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    // a live cluster (--kubeconfig) replaces the fake API server
    let kubeconfig = live_kubeconfig.clone().unwrap_or_else(|| work.join("kubeconfig"));
    let _api = if live_kubeconfig.is_none() && cases.iter().any(|c| c.needs_k8s) {
        let objs = crate::fakeapi::generate_with(K8S_SERVICES, K8S_NAMESPACES, true);
        let (addr, task) = rt.block_on(crate::fakeapi::serve(objs))?;
        fs::write(&kubeconfig, kubeconfig_for(&addr.to_string()))?;
        Some(task)
    } else {
        None
    };

    // the dnstap sink: accepts Frame Streams on a unix socket and counts
    // the messages
    let dnstap_sock = work.join("dnstap.sock");
    let dnstap_frames = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let _sink = if cases.iter().any(|c| c.corefile.contains("{DNSTAP}")) {
        let _ = fs::remove_file(&dnstap_sock);
        let _guard = rt.enter();
        let l = tokio::net::UnixListener::bind(&dnstap_sock).context("binding the dnstap sink")?;
        let frames = dnstap_frames.clone();
        Some(rt.spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let frames = frames.clone();
                tokio::spawn(kerndns_plugins::dnstap::framestream::read_stream(s, move |_| {
                    frames.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }));
            }
        }))
    } else {
        None
    };

    let mut vars: BTreeMap<&str, String> = BTreeMap::new();
    vars.insert("BENCH", bench.display().to_string());
    vars.insert("FIX", fix.display().to_string());
    vars.insert("BACKEND", backend_port.to_string());
    vars.insert("BACKEND_DOT", backend_dot.to_string());
    vars.insert("BACKEND_GRPC", backend_grpc.to_string());
    vars.insert("DNSTAP", dnstap_sock.display().to_string());
    vars.insert("KUBECONFIG", kubeconfig.display().to_string());
    vars.insert("ETCD", etcd_port.to_string());

    let servers = [("CoreDNS", &coredns), ("KernDNS", &kerndns)];
    let mut results: Vec<(Case, [Option<Result1>; 2], u32)> = Vec::new();
    let mut failed = Vec::new();
    for case in &cases {
        eprintln!("== level {} {}: {}", case.level, case.name, case.about);
        let mut v = vars.clone();
        v.insert("DIR", case.dir.display().to_string());
        let queries = match (&live_kubeconfig, &case.live_queries) {
            (Some(_), Some(live)) => live,
            _ => &case.queries,
        };
        let q = PathBuf::from(render(queries, &v));
        let mut rate = None;
        let mut res: [Option<Result1>; 2] = [None, None];
        for (i, (label, bin)) in servers.iter().enumerate() {
            let port = free_port()?;
            v.insert("PORT", port.to_string());
            let cf = work.join(format!("{}-{label}.conf", case.name.replace('/', "-")));
            fs::write(&cf, render(&case.corefile, &v))?;
            // fixed rate: half of CoreDNS's max, so both are measured unsaturated
            // with --runs N, the run with the median CPU time per query
            let mut runs_done = Vec::new();
            let mut err = None;
            let frames0 = dnstap_frames.load(std::sync::atomic::Ordering::Relaxed);
            let args: &[String] = if *label == "KernDNS" && !case.bridge.is_empty() {
                &bridge_args
            } else {
                &[]
            };
            for _ in 0..runs {
                match measure(&cpus, bin, args, &cf, port, case, &q, secs, rate) {
                    Ok((r, used)) => {
                        rate = Some(used);
                        runs_done.push(r);
                    }
                    Err(e) => {
                        err = Some(e);
                        break;
                    }
                }
            }
            if let Some(e) = err {
                eprintln!("   {label:8} failed: {e:#}");
                failed.push(format!("{} ({label})", case.name));
                continue;
            }
            runs_done.sort_by(|a, b| a.cpu_us.total_cmp(&b.cpu_us));
            let r = runs_done.swap_remove(runs_done.len() / 2);
            let used = rate.unwrap_or(0);
            eprintln!(
                "   {label:8} max {:>8.0} qps | @{} qps avg {:>6.0}µs sd {:>6.0}µs max {:>7.0}µs | {:.2} CPU µs/q | {:.1} MiB | {}",
                r.max.qps,
                used,
                r.fixed.avg_us,
                r.fixed.stddev_us,
                r.fixed.max_us,
                r.cpu_us,
                r.rss_mib,
                r.max.rcodes()
            );
            if r.max.lost > r.max.sent * 0.01 {
                eprintln!(
                    "   warning: {label} lost {:.1}% of queries at max load",
                    r.max.lost / r.max.sent * 100.0
                );
            }
            if case.corefile.contains("{DNSTAP}") {
                // give the last buffered messages a moment to arrive
                std::thread::sleep(Duration::from_millis(1500));
                let n = dnstap_frames.load(std::sync::atomic::Ordering::Relaxed) - frames0;
                eprintln!("   {label:8} dnstap sink received {n} messages");
            }
            res[i] = Some(r);
        }
        if let [Some(a), Some(b)] = &res
            && rcodes_differ(&a.max.rcodes, &b.max.rcodes)
        {
            eprintln!(
                "   warning: response codes differ: CoreDNS {} / KernDNS {}",
                a.max.rcodes(),
                b.max.rcodes()
            );
        }
        results.push((case.clone(), res, rate.unwrap_or(0)));
    }

    let report = report(&results)?;
    let out = work.join("report.md");
    fs::write(&out, &report)?;
    println!("\n{report}\nwritten to {}", out.display());
    if !failed.is_empty() {
        bail!("failed: {}", failed.join(", "));
    }
    Ok(())
}

/// The plugins in the bridge the benchmarks build.
fn bridge_plugins() -> Vec<&'static str> {
    crate::DEFAULT_BRIDGE_PLUGINS.split(',').collect()
}

/// SkyDNS services in etcd: (key, value) pairs and queries for them.
/// Every other service has two instances, every fifth an IPv6 address.
fn etcd_records(n: u32) -> Result<(Vec<(String, String)>, String)> {
    let mut kv = Vec::new();
    for i in 0..n {
        let key = format!("/skydns/local/skydns/svc{i}");
        let host = |j: u32| {
            if i % 5 == 0 {
                format!("fd00::{j}:{i:x}")
            } else {
                format!("10.{j}.{}.{}", i >> 8, i & 255)
            }
        };
        let val = |j: u32| format!(r#"{{"host":"{}","port":8080,"ttl":60}}"#, host(j));
        if i % 2 == 0 {
            kv.push((format!("{key}/a"), val(1)));
            kv.push((format!("{key}/b"), val(2)));
        } else {
            kv.push((key, val(1)));
        }
    }
    // services (A, AAAA, SRV), names not in etcd, and names forwarded
    let mut q = String::new();
    for i in 0..2000 {
        let k = (i * 7) % n;
        match i % 8 {
            0..=2 => writeln!(q, "svc{k}.skydns.local A")?,
            3 => writeln!(q, "svc{}.skydns.local AAAA", k / 5 * 5)?,
            4 => writeln!(q, "svc{k}.skydns.local SRV")?,
            5 => writeln!(q, "nx{k}.skydns.local A")?,
            _ => writeln!(q, "www{k}.example.org A")?,
        }
    }
    Ok((kv, q))
}

fn base64(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// A throwaway etcd on `port` filled with [`etcd_records`] (through its
/// JSON gateway); writes the queries to `{FIX}/q-etcd.txt`.
fn start_etcd(work: &Path, port: u16, cpus: &str, fix: &Path) -> Result<Proc> {
    use std::io::{Read, Write};
    let data = work.join("etcd-data");
    let _ = fs::remove_dir_all(&data);
    let url = format!("http://127.0.0.1:{port}");
    let child = Command::new("taskset")
        .args(["-c", cpus, "etcd", "--data-dir"])
        .arg(&data)
        .args(["--listen-client-urls", &url, "--advertise-client-urls", &url])
        .args(["--listen-peer-urls", &format!("http://127.0.0.1:{}", free_port()?)])
        .stdout(Stdio::null())
        .stderr(fs::File::create(work.join("etcd.log"))?)
        .spawn()
        .context("starting etcd (is it installed?)")?;
    let etcd = Proc(child);
    let (kv, queries) = etcd_records(500)?;
    let put = |k: &str, v: &str| -> Result<bool> {
        let body = format!(
            r#"{{"key":"{}","value":"{}"}}"#,
            base64(k.as_bytes()),
            base64(v.as_bytes())
        );
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port))?;
        write!(
            s,
            "POST /v3/kv/put HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
        let mut resp = String::new();
        s.read_to_string(&mut resp)?;
        Ok(resp.starts_with("HTTP/1.1 200"))
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    // the first put also waits until etcd is up and has a leader
    while !put(&kv[0].0, &kv[0].1).unwrap_or(false) {
        if Instant::now() > deadline {
            bail!(
                "etcd did not start on port {port} (see {})",
                work.join("etcd.log").display()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    for (k, v) in &kv[1..] {
        if !put(k, v)? {
            bail!("etcd: writing {k} failed");
        }
    }
    fs::write(fix.join("q-etcd.txt"), queries)?;
    Ok(etcd)
}

pub(crate) fn kubeconfig_for(addr: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Config\nclusters:\n- name: fake\n  cluster:\n    server: http://{addr}\ncontexts:\n- name: fake\n  context:\n    cluster: fake\n    user: fake\ncurrent-context: fake\nusers:\n- name: fake\n  user: {{}}\n"
    )
}

fn report(results: &[(Case, [Option<Result1>; 2], u32)]) -> Result<String> {
    let mut report = String::new();
    let base = results
        .iter()
        .find(|(c, _, _)| c.name == "whoami")
        .map(|(_, r, _)| r.clone());
    let fmt_qps = |r: &Option<Result1>| r.as_ref().map_or("-".into(), |r| format!("{:.0}k", r.max.qps / 1000.0));
    let added = |r: &Option<Result1>, b: &Option<Result1>| match (r, b) {
        (Some(r), Some(b)) => format!("{:+.1}", r.cpu_us - b.cpu_us),
        _ => "-".into(),
    };
    if let Some(base) = &base {
        writeln!(
            report,
            "Level 2: CPU µs per query added over the whoami baseline, and max QPS.\n"
        )?;
        writeln!(
            report,
            "| case | CoreDNS +µs/q | KernDNS +µs/q | CoreDNS QPS | KernDNS QPS | responses |"
        )?;
        writeln!(report, "|---|---:|---:|---:|---:|---|")?;
        for (c, r, _) in results.iter().filter(|(c, _, _)| c.level == 2) {
            let (cd, kd) = if c.name == "whoami" {
                (
                    r[0].as_ref().map_or("-".into(), |r| format!("{:.1} (base)", r.cpu_us)),
                    r[1].as_ref().map_or("-".into(), |r| format!("{:.1} (base)", r.cpu_us)),
                )
            } else {
                (added(&r[0], &base[0]), added(&r[1], &base[1]))
            };
            let codes = r[1]
                .as_ref()
                .or(r[0].as_ref())
                .map_or(String::new(), |r| r.max.rcodes());
            writeln!(
                report,
                "| {} | {cd} | {kd} | {} | {} | {codes} |",
                c.name,
                fmt_qps(&r[0]),
                fmt_qps(&r[1])
            )?;
        }
        writeln!(report)?;
    }
    writeln!(
        report,
        "Overview: CoreDNS → KernDNS, with KernDNS's change relative to CoreDNS.\n"
    )?;
    writeln!(report, "| level | case | max QPS | CPU µs / query | peak RSS |")?;
    writeln!(report, "|---|---|---|---|---|")?;
    for (c, r, _) in results {
        let (Some(cd), Some(kd)) = (&r[0], &r[1]) else {
            writeln!(report, "| {} | {} | failed | | |", c.level, c.name)?;
            continue;
        };
        writeln!(
            report,
            "| {} | {} | {} | {} | {} |",
            c.level,
            c.name,
            compare(cd.max.qps / 1000.0, kd.max.qps / 1000.0, 0, "k"),
            compare(cd.cpu_us, kd.cpu_us, 1, ""),
            compare(cd.rss_mib, kd.rss_mib, 0, " MiB"),
        )?;
    }
    writeln!(report)?;
    writeln!(
        report,
        "| level | case | server | max QPS | avg latency @ fixed rate | stddev | max | CPU µs / query | peak RSS |"
    )?;
    writeln!(report, "|---|---|---|---:|---:|---:|---:|---:|---:|")?;
    for (c, res, rate) in results {
        for (label, r) in ["CoreDNS", "KernDNS"].iter().zip(res) {
            let Some(r) = r else {
                writeln!(report, "| {} | {} | {label} | failed | | | | | |", c.level, c.name)?;
                continue;
            };
            writeln!(
                report,
                "| {} | {} | {label} | {:.0} | {:.0} µs @ {rate} qps | {:.0} µs | {:.1} ms | {:.2} | {:.1} MiB |",
                c.level,
                c.name,
                r.max.qps,
                r.fixed.avg_us,
                r.fixed.stddev_us,
                r.fixed.max_us / 1000.0,
                r.cpu_us,
                r.rss_mib
            )?;
        }
    }
    Ok(report)
}

/// `a → b (+x%)`: a CoreDNS value, the KernDNS value and KernDNS's change
/// relative to CoreDNS.
fn compare(a: f64, b: f64, decimals: usize, unit: &str) -> String {
    let pct = if a > 0.0 {
        format!(" ({:+.0}%)", (b / a - 1.0) * 100.0)
    } else {
        String::new()
    };
    format!("{a:.decimals$} → {b:.decimals$}{unit}{pct}")
}

/// RSS (current, peak) in MiB.
fn rss(pid: u32) -> (f64, f64) {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let get = |k: &str| {
        status
            .lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0)
            / 1024.0
    };
    (get("VmRSS"), get("VmHWM"))
}

/// One A query; true if it got an answer record.
fn resolves(port: u16, name: &str) -> bool {
    let Ok(sock) = std::net::UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
    let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.trim_end_matches('.').split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    if sock.send_to(&q, ("127.0.0.1", port)).is_err() {
        return false;
    }
    let mut b = [0u8; 512];
    match sock.recv_from(&mut b) {
        Ok((n, _)) => n > 7 && (b[3] & 0x0f) == 0 && (b[6] != 0 || b[7] != 0),
        Err(_) => false,
    }
}

/// `cargo xtask k8s-bench [--sizes 1000,10000] [--duration S]`: the
/// kubernetes plugin at scale against a fake API server.
pub fn k8s(args: &[String]) -> Result<()> {
    let mut sizes = vec![1000usize, 10000, 50000];
    let mut secs = 10u32;
    let mut coredns_bin = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--sizes" => {
                sizes = it
                    .next()
                    .context("--sizes needs a list")?
                    .split(',')
                    .map(|s| s.parse())
                    .collect::<Result<_, _>>()?
            }
            "--duration" => secs = it.next().context("--duration needs seconds")?.parse()?,
            "--coredns" => coredns_bin = Some(PathBuf::from(it.next().context("--coredns needs a path")?)),
            other => bail!("unknown argument {other}"),
        }
    }
    let root = root();
    let work = root.join("target/k8s-bench");
    fs::create_dir_all(&work)?;
    let kerndns = build_kerndns(&root)?;
    let coredns = coredns(&root, coredns_bin)?;
    let cpus = cpus();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let mut report = String::new();
    writeln!(
        report,
        "| services | server | sync time | RSS after sync | peak RSS | max QPS | CPU s / 1M queries |"
    )?;
    writeln!(report, "|---:|---|---:|---:|---:|---:|---:|")?;
    for &n in &sizes {
        let namespaces = (n / 100).clamp(1, 500);
        eprintln!("== {n} services, {} endpoints, {namespaces} namespaces", n * 3);
        let (api_addr, api_task) = rt.block_on(crate::fakeapi::serve(crate::fakeapi::generate(n, namespaces)))?;
        let kubeconfig = work.join("kubeconfig");
        fs::write(&kubeconfig, kubeconfig_for(&api_addr.to_string()))?;
        // queries: service A, endpoint A (hostnames from addresses), SRV, PTR
        let q = work.join(format!("q-{n}.txt"));
        let mut qs = String::new();
        for i in 0..2000 {
            let s = (i * 7919) % n;
            let ns = s % namespaces;
            match i % 4 {
                0 | 1 => writeln!(qs, "svc-{s}.ns-{ns}.svc.cluster.local A")?,
                2 => writeln!(qs, "_http._tcp.svc-{s}.ns-{ns}.svc.cluster.local SRV")?,
                _ => writeln!(
                    qs,
                    "{}.{}.{}.10.in-addr.arpa PTR",
                    s & 255,
                    (s >> 8) & 255,
                    96 + (s >> 16)
                )?,
            }
        }
        fs::write(&q, qs)?;
        let last = format!("svc-{}.ns-{}.svc.cluster.local", n - 1, (n - 1) % namespaces);

        for (label, bin) in [("CoreDNS", &coredns), ("KernDNS", &kerndns)] {
            let port = free_port()?;
            let cf = work.join(format!("{label}-{n}.conf"));
            fs::write(
                &cf,
                format!(
                    "cluster.local:{port} in-addr.arpa:{port} {{\n    bind 127.0.0.1\n    kubernetes cluster.local in-addr.arpa {{\n        kubeconfig {}\n        startup_timeout 120s\n    }}\n}}\n",
                    kubeconfig.display()
                ),
            )?;
            let t0 = Instant::now();
            let mut child = Command::new("taskset")
                .args(["-c", &cpus.server])
                .arg(bin)
                .args(["-conf"])
                .arg(&cf)
                .arg("-quiet")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let deadline = Instant::now() + Duration::from_secs(180);
            while !resolves(port, &last) {
                if child.try_wait()?.is_some() || Instant::now() > deadline {
                    let _ = child.kill();
                    bail!("{label} did not serve {last}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let sync = t0.elapsed();
            let p = Proc(child);
            let pid = p.0.id();
            std::thread::sleep(Duration::from_secs(1));
            let (rss_sync, _) = rss(pid);
            dnsperf(&cpus, port, &q, 2, None, &[])?;
            let (cpu0, _) = proc_usage(pid);
            let max = dnsperf(&cpus, port, &q, secs, None, &[])?;
            let (cpu1, _) = proc_usage(pid);
            let (_, peak) = rss(pid);
            let cpu = if max.sent > 0.0 {
                (cpu1 - cpu0) / max.sent * 1e6
            } else {
                0.0
            };
            eprintln!(
                "   {label:8} sync {:>6.2}s | RSS {:>7.1} MiB (peak {:>7.1}) | {:>8.0} qps | {:.2} CPU s/Mq",
                sync.as_secs_f64(),
                rss_sync,
                peak,
                max.qps,
                cpu
            );
            writeln!(
                report,
                "| {n} | {label} | {:.2} s | {:.1} MiB | {:.1} MiB | {:.0} | {:.2} |",
                sync.as_secs_f64(),
                rss_sync,
                peak,
                max.qps,
                cpu
            )?;
        }
        api_task.abort();
    }
    let out = work.join("report.md");
    fs::write(&out, &report)?;
    println!("\n{report}\nwritten to {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_shows_change() {
        assert_eq!(compare(40.0, 83.0, 0, "k"), "40 → 83k (+108%)");
        assert_eq!(compare(49.8, 31.2, 1, ""), "49.8 → 31.2 (-37%)");
        assert_eq!(compare(0.0, 5.0, 0, " MiB"), "0 → 5 MiB");
    }

    #[test]
    fn rcodes() {
        let out = "  Queries lost:         0 (0.00%)\n\n  Response codes:       NOERROR 900 (90.00%), NXDOMAIN 100 (10.00%)\n";
        let got = parse_rcodes(out);
        assert_eq!(got, vec![("NOERROR".to_string(), 90.0), ("NXDOMAIN".to_string(), 10.0)]);
        assert!(!rcodes_differ(&got, &got));
        assert!(rcodes_differ(&got, &[("NOERROR".to_string(), 100.0)]));
    }

    #[test]
    fn placeholders_skip_templates() {
        let text = "{PORT} {{ .Name }} h{1}.example.net {FIX}/db";
        assert_eq!(placeholders(text), vec!["PORT", "FIX"]);
    }

    #[test]
    fn scenarios_are_complete() {
        check(&root().join("bench")).unwrap();
    }
}
