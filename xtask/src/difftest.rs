//! `cargo xtask difftest`: differential testing against CoreDNS.
//!
//! For every zone fixture embedded in CoreDNS's `plugin/file` tests, serve
//! it with `file` from both CoreDNS (built from third_party/coredns) and
//! kerndns, then let `go/difftest` send generated queries to both and
//! report differences.

use std::fs;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::root;

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port that is free for both UDP and TCP (servers bind both).
fn free_port() -> Result<u16> {
    for _ in 0..100 {
        let port = UdpSocket::bind("127.0.0.1:0")?.local_addr()?.port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    bail!("no port free for both UDP and TCP")
}

/// Two different free ports.
fn two_ports() -> Result<(u16, u16)> {
    let a = free_port()?;
    loop {
        let b = free_port()?;
        if b != a {
            return Ok((a, b));
        }
    }
}

/// A minimal query for `. SOA`; any answer means the server is up.
fn probe(port: u16) -> bool {
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
    let q = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 1];
    if sock.send_to(&q, ("127.0.0.1", port)).is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    sock.recv_from(&mut buf).is_ok()
}

/// Start a server; `Ok(None)` if it exited (rejected the config).
fn start(bin: &Path, corefile: &Path, port: u16, log: &Path) -> Result<Option<Server>> {
    let child = Command::new(bin)
        .arg("-conf")
        .arg(corefile)
        .arg("-quiet")
        .stdout(Stdio::from(fs::File::create(log)?))
        .stderr(Stdio::from(fs::File::create(log.with_extension("err"))?))
        .spawn()
        .with_context(|| format!("starting {}", bin.display()))?;
    let mut s = Server(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if s.0.try_wait()?.is_some() {
            return Ok(None);
        }
        if probe(port) {
            return Ok(Some(s));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("{} did not start listening on {port}", bin.display())
}

/// `const name = \`...\`` string constants in a Go file.
fn go_raw_consts(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(i) = rest.find("\nconst ") {
        rest = &rest[i + 7..];
        let Some(eq) = rest.find('=') else { break };
        let name = rest[..eq].trim().to_string();
        let after = rest[eq + 1..].trim_start();
        if !after.starts_with('`') || name.contains(char::is_whitespace) {
            continue;
        }
        let body = &after[1..];
        let Some(end) = body.find('`') else { break };
        out.push((name, body[..end].to_string()));
        rest = &body[end + 1..];
    }
    out
}

pub fn run(args: &[String]) -> Result<()> {
    let mut release = false;
    let mut only: Option<String> = None;
    let mut show = "10".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--release" => release = true,
            "--zone" => only = Some(it.next().context("--zone needs a value")?.clone()),
            "--show" => show = it.next().context("--show needs a value")?.clone(),
            other => bail!("unknown argument {other}"),
        }
    }

    let root = root();
    let upstream = root.join("third_party/coredns");
    let work = root.join("target/difftest");
    let zones_dir = work.join("zones");
    fs::create_dir_all(&zones_dir)?;

    // build kerndns, CoreDNS and the query tool
    let mut build = Command::new(env!("CARGO"));
    build.current_dir(&root).args(["build", "--package", "kerndns"]);
    if release {
        build.arg("--release");
    }
    if !build.status()?.success() {
        bail!("building kerndns failed");
    }
    let kerndns = root
        .join("target")
        .join(if release { "release" } else { "debug" })
        .join("kerndns");
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
    let tool = root.join("target/difftest-tool");
    if !Command::new("go")
        .current_dir(root.join("go/difftest"))
        .args(["build", "-o"])
        .arg(&tool)
        .arg(".")
        .status()?
        .success()
    {
        bail!("building go/difftest failed");
    }

    // zone fixtures from plugin/file
    let mut zones: Vec<(String, PathBuf)> = Vec::new();
    let mut srcs: Vec<PathBuf> = fs::read_dir(upstream.join("plugin/file"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "go"))
        .collect();
    srcs.sort();
    for src in srcs {
        for (name, body) in go_raw_consts(&fs::read_to_string(&src)?) {
            if only.as_ref().is_some_and(|o| o != &name) {
                continue;
            }
            let path = zones_dir.join(format!("{name}.db"));
            fs::write(&path, body)?;
            zones.push((name, path));
        }
    }
    if zones.is_empty() {
        bail!("no zone fixtures found");
    }

    let mut total_diffs = 0;
    let mut summary = Vec::new();
    for (name, path) in &zones {
        let out = Command::new(&tool)
            .args(["-print-origin", "-zone"])
            .arg(path)
            .output()?;
        let origin = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if origin.is_empty() {
            summary.push(format!("  skip  {name}: no SOA"));
            continue;
        }
        let (pa, pb) = two_ports()?;
        let cf = |port: u16| {
            format!(
                "{origin}:{port} {{\n    bind 127.0.0.1\n    file {}\n}}\n",
                path.display()
            )
        };
        let (cfa, cfb) = (
            work.join(format!("{name}.coredns.conf")),
            work.join(format!("{name}.kerndns.conf")),
        );
        fs::write(&cfa, cf(pa))?;
        fs::write(&cfb, cf(pb))?;
        let a = start(&coredns, &cfa, pa, &work.join(format!("{name}.coredns.log")))?;
        let b = start(&kerndns, &cfb, pb, &work.join(format!("{name}.kerndns.log")))?;
        match (&a, &b) {
            (None, None) => {
                summary.push(format!("  ok    {name}: both reject the zone"));
                continue;
            }
            (Some(_), None) => {
                total_diffs += 1;
                let err = fs::read_to_string(work.join(format!("{name}.kerndns.err"))).unwrap_or_default();
                summary.push(format!(
                    "  DIFF  {name}: CoreDNS loads it, kerndns does not: {}",
                    err.trim()
                ));
                continue;
            }
            (None, Some(_)) => {
                total_diffs += 1;
                let mut err = fs::read_to_string(work.join(format!("{name}.coredns.log"))).unwrap_or_default();
                err += &fs::read_to_string(work.join(format!("{name}.coredns.err"))).unwrap_or_default();
                let last = err.lines().rfind(|l| !l.contains("maxprocs")).unwrap_or("").to_string();
                summary.push(format!("  DIFF  {name}: kerndns loads it, CoreDNS does not: {last}"));
                continue;
            }
            _ => {}
        }
        let out = Command::new(&tool)
            .args([
                "-a",
                &format!("127.0.0.1:{pa}"),
                "-b",
                &format!("127.0.0.1:{pb}"),
                "-origin",
                &origin,
                "-show",
                &show,
                "-zone",
            ])
            .arg(path)
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let last = text.lines().last().unwrap_or("").to_string();
        if out.status.success() {
            summary.push(format!("  ok    {name} ({origin}): {last}"));
        } else {
            let n: usize = last
                .split(", ")
                .nth(1)
                .and_then(|s| s.split(' ').next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
            total_diffs += n;
            summary.push(format!("  DIFF  {name} ({origin}): {last}"));
            print!("== {name} ({origin})\n{text}");
        }
        drop(a);
        drop(b);
    }
    println!("\nzones:");
    for s in &summary {
        println!("{s}");
    }
    if total_diffs > 0 {
        println!("\n{total_diffs} differences");
        std::process::exit(1);
    }
    println!("\nno differences");
    Ok(())
}

/// Labels of a reverse name for an IP.
fn reverse_name(ip: &str) -> Option<String> {
    match ip.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0]))
        }
        std::net::IpAddr::V6(v6) => {
            let hex: String = v6.octets().iter().map(|b| format!("{b:02x}")).collect();
            let nibbles: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
            Some(format!("{}.ip6.arpa.", nibbles.join(".")))
        }
    }
}

fn dashed(ip: &str) -> String {
    let d = ip.replace(['.', ':'], "-");
    if d.ends_with('-') { format!("{d}0") } else { d }
}

/// Queries for everything in the cluster (`kubectl get ... -o json`).
fn k8s_queries(context: &str, zone: &str) -> Result<String> {
    let get = |what: &str| -> Result<serde_json::Value> {
        let out = Command::new("kubectl")
            .args(["--context", context, "get", what, "-A", "-o", "json"])
            .output()?;
        if !out.status.success() {
            bail!("kubectl get {what}: {}", String::from_utf8_lossy(&out.stderr));
        }
        Ok(serde_json::from_slice(&out.stdout)?)
    };
    let mut q: Vec<String> = Vec::new();
    let mut add = |n: String, types: &[&str]| {
        for t in types {
            q.push(format!("{n} {t}"));
        }
    };
    let all = ["A", "AAAA", "SRV", "TXT", "CNAME", "MX", "PTR", "NS", "SOA", "HINFO"];
    add(zone.to_string(), &["SOA", "NS", "A", "AAAA", "TXT", "MX"]);
    add(format!("ns.dns.{zone}"), &["A", "AAAA", "TXT"]);
    add(format!("dns-version.{zone}"), &["TXT", "A"]);
    add(format!("nx.{zone}"), &["A", "TXT"]);
    add(format!("svc.{zone}"), &["A", "NS"]);
    add(format!("pod.{zone}"), &["A"]);
    add(format!("nosuch.nsnoexist.svc.{zone}"), &["A", "SRV"]);
    add(format!("a.b.c.d.e.svc.{zone}"), &["A"]);
    add(format!("x.y.foo.{zone}"), &["A"]);
    add("1.0.0.10.in-addr.arpa.".into(), &["PTR"]);
    for n in [
        "example.com.",
        "dns.example.com.",
        "ns1.dns.example.com.",
        "x.ns1.dns.example.com.",
        "testns.example.com.",
        "nosuch.testns.example.com.",
    ] {
        add(n.into(), &["SOA", "NS", "A", "AAAA", "TXT"]);
    }

    let mut namespaces = std::collections::BTreeSet::new();
    let svcs = get("services")?;
    for s in svcs["items"].as_array().into_iter().flatten() {
        let name = s["metadata"]["name"].as_str().unwrap_or_default();
        let ns = s["metadata"]["namespace"].as_str().unwrap_or_default();
        namespaces.insert(ns.to_string());
        let fq = format!("{name}.{ns}.svc.{zone}");
        add(fq.clone(), &all);
        // the same service under the k8s_external zone
        let ext = format!("{name}.{ns}.example.com.");
        add(ext.clone(), &["A", "AAAA", "SRV", "TXT", "PTR"]);
        for p in s["spec"]["ports"].as_array().into_iter().flatten() {
            if let Some(pn) = p["name"].as_str() {
                let proto = p["protocol"].as_str().unwrap_or("TCP").to_ascii_lowercase();
                add(format!("_{pn}._{proto}.{ext}"), &["SRV"]);
            }
        }
        add(format!("nosuch-{name}.{ns}.svc.{zone}"), &["A"]);
        add(fq.to_uppercase(), &["A", "SRV"]);
        add(format!("_nosuch._tcp.{fq}"), &["SRV"]);
        for p in s["spec"]["ports"].as_array().into_iter().flatten() {
            let proto = p["protocol"].as_str().unwrap_or("TCP").to_ascii_lowercase();
            if let Some(pn) = p["name"].as_str() {
                add(format!("_{pn}._{proto}.{fq}"), &["SRV", "A"]);
            }
            add(format!("_*._{proto}.{fq}"), &["SRV"]);
        }
        for ip in s["spec"]["clusterIPs"].as_array().into_iter().flatten() {
            if let Some(r) = ip.as_str().and_then(reverse_name) {
                add(r, &["PTR"]);
            }
        }
    }
    for ns in &namespaces {
        add(format!("{ns}.svc.{zone}"), &["A", "SRV"]);
        add(format!("{ns}.pod.{zone}"), &["A"]);
    }
    let eps = get("endpointslices")?;
    for e in eps["items"].as_array().into_iter().flatten() {
        let ns = e["metadata"]["namespace"].as_str().unwrap_or_default();
        let Some(svc) = e["metadata"]["labels"]["kubernetes.io/service-name"].as_str() else {
            continue;
        };
        for end in e["endpoints"].as_array().into_iter().flatten() {
            for a in end["addresses"].as_array().into_iter().flatten() {
                let ip = a.as_str().unwrap_or_default();
                add(format!("{}.{svc}.{ns}.svc.{zone}", dashed(ip)), &["A", "AAAA", "SRV"]);
                if let Some(r) = reverse_name(ip) {
                    add(r, &["PTR"]);
                }
            }
            if let Some(h) = end["hostname"].as_str() {
                add(format!("{h}.{svc}.{ns}.svc.{zone}"), &["A", "AAAA", "SRV"]);
            }
            if let Some(t) = end["targetRef"]["name"].as_str() {
                add(format!("{t}.{svc}.{ns}.svc.{zone}"), &["A"]);
            }
        }
    }
    let pods = get("pods")?;
    for p in pods["items"].as_array().into_iter().flatten() {
        let ns = p["metadata"]["namespace"].as_str().unwrap_or_default();
        for ip in p["status"]["podIPs"].as_array().into_iter().flatten() {
            let ip = ip["ip"].as_str().unwrap_or_default();
            add(format!("{}.{ns}.pod.{zone}", dashed(ip)), &["A", "AAAA"]);
            add(format!("{}.wrongns.pod.{zone}", dashed(ip)), &["A"]);
            if let Some(r) = reverse_name(ip) {
                add(r, &["PTR"]);
            }
        }
    }
    q.sort();
    q.dedup();
    Ok(q.join("\n"))
}

/// `cargo xtask k8s-difftest --context NAME`: the same cluster served by
/// CoreDNS and kerndns (both outside the cluster, via kubeconfig).
pub fn k8s(args: &[String]) -> Result<()> {
    let mut context = String::from("kind-kerndns-difftest");
    let mut show = "10".to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--context" => context = it.next().context("--context needs a value")?.clone(),
            "--show" => show = it.next().context("--show needs a value")?.clone(),
            other => bail!("unknown argument {other}"),
        }
    }
    let root = root();
    let upstream = root.join("third_party/coredns");
    let work = root.join("target/k8s-difftest");
    fs::create_dir_all(&work)?;

    let kc = Command::new("kubectl")
        .args(["config", "view", "--raw", "--minify", "--context", &context])
        .output()?;
    if !kc.status.success() {
        bail!("kubectl config view: {}", String::from_utf8_lossy(&kc.stderr));
    }
    let kubeconfig = work.join("kubeconfig");
    fs::write(&kubeconfig, &kc.stdout)?;

    if !Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "--package", "kerndns"])
        .status()?
        .success()
    {
        bail!("building kerndns failed");
    }
    let kerndns = root.join("target/debug/kerndns");
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
    let tool = root.join("target/difftest-tool");
    if !Command::new("go")
        .current_dir(root.join("go/difftest"))
        .args(["build", "-o"])
        .arg(&tool)
        .arg(".")
        .status()?
        .success()
    {
        bail!("building go/difftest failed");
    }

    let zone = "cluster.local.";
    let queries = work.join("queries.txt");
    let qs = k8s_queries(&context, zone)?;
    let n = qs.lines().count();
    fs::write(&queries, qs)?;
    eprintln!("{n} query names/types from the live cluster");

    let kc = kubeconfig.display().to_string();
    let variants: Vec<(&str, String)> = vec![
        (
            "kubeadm",
            format!(
                "kubeconfig {kc}\n        pods insecure\n        fallthrough in-addr.arpa ip6.arpa\n        ttl 30"
            ),
        ),
        (
            "verified",
            format!("kubeconfig {kc}\n        pods verified\n        endpoint_pod_names"),
        ),
        (
            "namespaces",
            format!("kubeconfig {kc}\n        namespaces testns other\n        ignore empty_service"),
        ),
        (
            "k8s_external",
            format!(
                "kubeconfig {kc}\n        pods insecure\n    }}\n    k8s_external example.com {{\n        headless"
            ),
        ),
    ];
    let mut total_diffs = 0;
    let mut summary = Vec::new();
    for (name, opts) in &variants {
        let (pa, pb) = two_ports()?;
        let cf = |port: u16| {
            format!(
                "{zone}:{port} in-addr.arpa.:{port} ip6.arpa.:{port} example.com.:{port} {{\n    bind 127.0.0.1\n    kubernetes cluster.local in-addr.arpa ip6.arpa {{\n        {opts}\n    }}\n}}\n"
            )
        };
        let (cfa, cfb) = (
            work.join(format!("{name}.coredns.conf")),
            work.join(format!("{name}.kerndns.conf")),
        );
        fs::write(&cfa, cf(pa))?;
        fs::write(&cfb, cf(pb))?;
        let a = start(&coredns, &cfa, pa, &work.join(format!("{name}.coredns.log")))?;
        let b = start(&kerndns, &cfb, pb, &work.join(format!("{name}.kerndns.log")))?;
        if a.is_none() || b.is_none() {
            bail!("{name}: a server failed to start (see {})", work.display());
        }
        // give both watchers time to sync
        std::thread::sleep(Duration::from_secs(3));
        let out = Command::new(&tool)
            .args([
                "-a",
                &format!("127.0.0.1:{pa}"),
                "-b",
                &format!("127.0.0.1:{pb}"),
                "-ignore-soa-serial",
                "-show",
                &show,
                "-queries",
            ])
            .arg(&queries)
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let last = text.lines().last().unwrap_or("").to_string();
        let answers = text
            .lines()
            .find(|l| l.starts_with("answers from A"))
            .unwrap_or("")
            .replace("answers from A", "CoreDNS answers");
        if out.status.success() {
            summary.push(format!("  ok    {name}: {last}\n          {answers}"));
        } else {
            let d: usize = last
                .split(", ")
                .nth(1)
                .and_then(|s| s.split(' ').next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
            total_diffs += d;
            summary.push(format!("  DIFF  {name}: {last}"));
            print!("== {name}\n{text}");
        }
    }
    println!("\nvariants:");
    for s in &summary {
        println!("{s}");
    }
    if total_diffs > 0 {
        println!("\n{total_diffs} differences");
        std::process::exit(1);
    }
    println!("\nno differences");
    Ok(())
}
