//! `cargo xtask bench`: CoreDNS vs KernDNS with dnsperf.
//!
//! Each scenario is a Corefile template (`{PORT}`, `{BACKEND}`, `{FIX}`)
//! plus a query file. Both servers get the same Corefile and fixtures and
//! are pinned to the same CPUs; dnsperf and the shared backend (an
//! authoritative CoreDNS that `forward` scenarios query) run on other CPUs.
//!
//! For every scenario and server: max QPS (dnsperf with many outstanding
//! queries), then latency at a fixed rate (half of CoreDNS's max QPS), CPU
//! time per million queries and peak RSS.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::root;

const SERVER_CPUS: &str = "0,1,4,5";
const DNSPERF_CPUS: &str = "2,6";
const BACKEND_CPUS: &str = "3,7";

struct Scenario {
    name: &'static str,
    about: &'static str,
    corefile: &'static str,
    queries: fn(&Path) -> Result<PathBuf>,
    /// Needs the shared upstream (for documentation; it always runs).
    #[allow(dead_code)]
    backend: bool,
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "whoami",
            about: "baseline: the cheapest possible chain",
            corefile: ".:{PORT} {\n    whoami\n}\n",
            queries: q_example,
            backend: false,
        },
        Scenario {
            name: "log",
            about: "log + whoami (log output to /dev/null)",
            corefile: ".:{PORT} {\n    log\n    whoami\n}\n",
            queries: q_example,
            backend: false,
        },
        Scenario {
            name: "prometheus",
            about: "prometheus + whoami",
            corefile: ".:{PORT} {\n    prometheus 127.0.0.1:0\n    whoami\n}\n",
            queries: q_example,
            backend: false,
        },
        Scenario {
            name: "hosts",
            about: "hosts file with 10k entries, A/AAAA/PTR hits",
            corefile: ".:{PORT} {\n    hosts {FIX}/hosts {\n        fallthrough\n    }\n    whoami\n}\n",
            queries: q_hosts,
            backend: false,
        },
        Scenario {
            name: "file",
            about: "authoritative zone, 10k names: hits, NXDOMAIN, wildcard, CNAME",
            corefile: "example.org:{PORT} {\n    file {FIX}/db.example.org\n}\n",
            queries: q_file,
            backend: false,
        },
        Scenario {
            name: "forward",
            about: "forward to a shared upstream (no cache)",
            corefile: ".:{PORT} {\n    forward . 127.0.0.1:{BACKEND}\n}\n",
            queries: q_file,
            backend: true,
        },
        Scenario {
            name: "cache",
            about: "cache in front of forward; all hits after warmup",
            corefile: ".:{PORT} {\n    cache\n    forward . 127.0.0.1:{BACKEND}\n}\n",
            queries: q_file,
            backend: true,
        },
        Scenario {
            name: "resolver",
            about: "common setup: errors, health, ready, prometheus, cache, forward, loop, reload",
            corefile: ".:{PORT} {\n    errors\n    health 127.0.0.1:0\n    ready 127.0.0.1:0\n    prometheus 127.0.0.1:0\n    cache 30\n    forward . 127.0.0.1:{BACKEND}\n    loop\n    reload\n}\n",
            queries: q_file,
            backend: true,
        },
    ]
}

fn q_example(dir: &Path) -> Result<PathBuf> {
    let p = dir.join("q-example.txt");
    let s: String = (0..1000).map(|i| format!("host{i}.example.org A\n")).collect();
    fs::write(&p, s)?;
    Ok(p)
}

fn q_hosts(dir: &Path) -> Result<PathBuf> {
    let p = dir.join("q-hosts.txt");
    let mut s = String::new();
    for i in 0..3000u32 {
        let n = i * 3;
        match i % 3 {
            0 => writeln!(s, "h{n}.hosts.example A")?,
            1 => writeln!(s, "h{n}.hosts.example AAAA")?,
            _ => writeln!(s, "{}.{}.10.in-addr.arpa PTR", n % 250 + 1, n / 250)?,
        }
    }
    fs::write(&p, s)?;
    Ok(p)
}

fn q_file(dir: &Path) -> Result<PathBuf> {
    let p = dir.join("q-file.txt");
    let mut s = String::new();
    for i in 0..4000u32 {
        let n = (i * 7) % 10000;
        match i % 8 {
            0..=3 => writeln!(s, "www{n}.example.org A")?,
            4 => writeln!(s, "www{n}.example.org AAAA")?,
            5 => writeln!(s, "nx{n}.example.org A")?,
            6 => writeln!(s, "x{n}.wild.example.org A")?,
            _ => writeln!(s, "alias{n}.example.org A")?,
        }
    }
    fs::write(&p, s)?;
    Ok(p)
}

fn write_fixtures(dir: &Path) -> Result<()> {
    let mut z = String::from(
        "$ORIGIN example.org.\n$TTL 3600\n@ IN SOA ns1 hostmaster 2024010101 7200 3600 1209600 300\n@ IN NS ns1\nns1 IN A 192.0.2.53\n*.wild IN A 192.0.2.99\n",
    );
    for i in 0..10000u32 {
        writeln!(z, "www{i} IN A 10.{}.{}.{}", i >> 16 & 255, i >> 8 & 255, i & 255)?;
        if i % 4 == 0 {
            writeln!(z, "www{i} IN AAAA fd00::{i:x}")?;
        }
        if i % 10 == 0 {
            writeln!(z, "alias{i} IN CNAME www{i}")?;
        }
    }
    fs::write(dir.join("db.example.org"), z)?;

    let mut h = String::new();
    for i in 0..10000u32 {
        writeln!(h, "10.{}.{}.{} h{i}.hosts.example", i / 250, i / 250, i % 250 + 1)?;
        writeln!(h, "fd00::{i:x} h{i}.hosts.example")?;
    }
    fs::write(dir.join("hosts"), h)?;
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
    Ok(std::net::UdpSocket::bind("127.0.0.1:0")?.local_addr()?.port())
}

fn wait_up(port: u16, child: &mut Child) -> Result<()> {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))?;
    let q = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 1];
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            bail!("server exited during startup");
        }
        let _ = sock.send_to(&q, ("127.0.0.1", port));
        let mut b = [0u8; 512];
        if sock.recv_from(&mut b).is_ok() {
            return Ok(());
        }
    }
    bail!("server did not start on port {port}")
}

fn start(bin: &Path, corefile: &Path, port: u16, cpus: &str) -> Result<Proc> {
    let mut child = Command::new("taskset")
        .args(["-c", cpus])
        .arg(bin)
        .arg("-conf")
        .arg(corefile)
        .arg("-quiet")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("starting {}", bin.display()))?;
    wait_up(port, &mut child)?;
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
}

fn dnsperf(port: u16, queries: &Path, secs: u32, rate: Option<u32>) -> Result<Run> {
    let mut cmd = Command::new("taskset");
    cmd.args([
        "-c",
        DNSPERF_CPUS,
        "dnsperf",
        "-s",
        "127.0.0.1",
        "-p",
        &port.to_string(),
        "-d",
    ])
    .arg(queries)
    .args(["-c", "32", "-T", "2", "-q", "500", "-l", &secs.to_string()])
    .env("LC_ALL", "C");
    if let Some(r) = rate {
        cmd.args(["-Q", &r.to_string()]);
    }
    let out = cmd.output().context("running dnsperf (is it installed?)")?;
    let text = String::from_utf8_lossy(&out.stdout);
    let num = |key: &str, idx: usize| -> f64 {
        text.lines()
            .find(|l| l.trim_start().starts_with(key))
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
    })
}

#[derive(Debug, Default, Clone)]
struct Result1 {
    max: Run,
    fixed: Run,
    cpu_per_mq: f64,
    rss_mib: f64,
}

/// Max QPS, then latency at `rate` (or half of this server's max), on one
/// server process. Returns the result and the rate used.
fn measure(bin: &Path, corefile: &Path, port: u16, q: &Path, secs: u32, rate: Option<u32>) -> Result<(Result1, u32)> {
    let p = start(bin, corefile, port, SERVER_CPUS)?;
    let pid = p.0.id();
    dnsperf(port, q, 2, None)?; // warm up (fills caches)
    let (cpu0, _) = proc_usage(pid);
    let max = dnsperf(port, q, secs, None)?;
    let (cpu1, _) = proc_usage(pid);
    let rate = rate.unwrap_or(((max.qps / 2.0) as u32).max(1000));
    let fixed = dnsperf(port, q, secs, Some(rate))?;
    let (_, rss) = proc_usage(pid);
    let cpu_per_mq = if max.sent > 0.0 {
        (cpu1 - cpu0) / max.sent * 1e6
    } else {
        0.0
    };
    Ok((
        Result1 {
            max,
            fixed,
            cpu_per_mq,
            rss_mib: rss,
        },
        rate,
    ))
}

pub fn run(args: &[String]) -> Result<()> {
    let mut only: Option<String> = None;
    let mut secs = 10u32;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--scenario" => only = Some(it.next().context("--scenario needs a value")?.clone()),
            "--duration" => secs = it.next().context("--duration needs seconds")?.parse()?,
            other => bail!("unknown argument {other}"),
        }
    }

    let root = root();
    let upstream = root.join("third_party/coredns");
    let work = root.join("target/bench");
    let fix = work.join("fixtures");
    fs::create_dir_all(&fix)?;
    write_fixtures(&fix)?;

    if !Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "--release", "--package", "kerndns"])
        .status()?
        .success()
    {
        bail!("building kerndns failed");
    }
    let kerndns = root.join("target/release/kerndns");
    let coredns = root.join("target/coredns-ref");
    if !Command::new("go")
        .current_dir(&upstream)
        .args(["build", "-o"])
        .arg(&coredns)
        .arg(".")
        .status()?
        .success()
    {
        bail!("building CoreDNS failed");
    }

    // the shared upstream for forward scenarios: CoreDNS serving the zone
    let backend_port = free_port()?;
    let backend_cf = work.join("backend.conf");
    fs::write(
        &backend_cf,
        format!(
            ".:{backend_port} {{\n    file {}/db.example.org example.org\n}}\n",
            fix.display()
        ),
    )?;
    let _backend = start(&coredns, &backend_cf, backend_port, BACKEND_CPUS)?;

    let mut report = String::new();
    writeln!(
        report,
        "| scenario | server | max QPS | avg latency @ fixed rate | stddev | max | CPU s / 1M queries | peak RSS |"
    )?;
    writeln!(report, "|---|---|---:|---:|---:|---:|---:|---:|")?;
    for sc in scenarios() {
        if only.as_deref().is_some_and(|o| o != sc.name) {
            continue;
        }
        eprintln!("== {}: {}", sc.name, sc.about);
        let q = (sc.queries)(&work)?;
        let mut rate = None;
        for (label, bin) in [("CoreDNS", &coredns), ("KernDNS", &kerndns)] {
            let port = free_port()?;
            let cf = work.join(format!("{}-{}.conf", sc.name, label));
            let text = sc
                .corefile
                .replace("{PORT}", &port.to_string())
                .replace("{BACKEND}", &backend_port.to_string())
                .replace("{FIX}", &fix.display().to_string());
            fs::write(&cf, text)?;
            // fixed rate: half of CoreDNS's max, so both are measured unsaturated
            let (r, used) = measure(bin, &cf, port, &q, secs, rate)?;
            rate = Some(used);
            eprintln!(
                "   {label:8} max {:>8.0} qps | @{} qps avg {:>6.0}µs sd {:>6.0}µs max {:>7.0}µs | {:.2} CPU s/Mq | {:.1} MiB",
                r.max.qps,
                rate.unwrap_or(0),
                r.fixed.avg_us,
                r.fixed.stddev_us,
                r.fixed.max_us,
                r.cpu_per_mq,
                r.rss_mib
            );
            writeln!(
                report,
                "| {} | {} | {:.0} | {:.0} µs @ {} qps | {:.0} µs | {:.1} ms | {:.2} | {:.1} MiB |",
                sc.name,
                label,
                r.max.qps,
                r.fixed.avg_us,
                rate.unwrap_or(0),
                r.fixed.stddev_us,
                r.fixed.max_us / 1000.0,
                r.cpu_per_mq,
                r.rss_mib
            )?;
            if r.max.lost > r.max.sent * 0.01 {
                eprintln!(
                    "   warning: {label} lost {:.1}% of queries at max load",
                    r.max.lost / r.max.sent * 100.0
                );
            }
        }
    }
    let out = work.join("report.md");
    fs::write(&out, &report)?;
    println!("\n{report}\nwritten to {}", out.display());
    Ok(())
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
            other => bail!("unknown argument {other}"),
        }
    }
    let root = root();
    let work = root.join("target/k8s-bench");
    fs::create_dir_all(&work)?;
    if !Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "--release", "--package", "kerndns"])
        .status()?
        .success()
    {
        bail!("building kerndns failed");
    }
    let kerndns = root.join("target/release/kerndns");
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
        fs::write(
            &kubeconfig,
            format!(
                "apiVersion: v1\nkind: Config\nclusters:\n- name: fake\n  cluster:\n    server: http://{api_addr}\ncontexts:\n- name: fake\n  context:\n    cluster: fake\n    user: fake\ncurrent-context: fake\nusers:\n- name: fake\n  user: {{}}\n"
            ),
        )?;
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
                .args(["-c", SERVER_CPUS])
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
            dnsperf(port, &q, 2, None)?;
            let (cpu0, _) = proc_usage(pid);
            let max = dnsperf(port, &q, secs, None)?;
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
