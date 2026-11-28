//! `cargo xtask difftest`: differential testing against CoreDNS.
//!
//! For every zone fixture embedded in CoreDNS's `plugin/file` tests, serve
//! it with `file` from both CoreDNS (built from third_party/coredns) and
//! kerndns, then let `go/difftest` send generated queries to both and
//! report differences.
//!
//! With `--dnssec` both servers also sign every zone on the fly (`dnssec`
//! with one ECDSA key): RRSIGs are compared without their signature and
//! validity times, which differ by design, and every RRSIG from either
//! server must verify with the key.

use std::collections::BTreeSet;
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
fn start(bin: &Path, args: &[String], corefile: &Path, port: u16, log: &Path) -> Result<Option<Server>> {
    let child = Command::new(bin)
        .args(args)
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
    let mut dnssec = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--release" => release = true,
            "--zone" => only = Some(it.next().context("--zone needs a value")?.clone()),
            "--show" => show = it.next().context("--show needs a value")?.clone(),
            "--dnssec" => dnssec = true,
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
    let coredns = crate::coredns_ref(&root)?;
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

    // A key whose owner is the root can sign every zone (dnssec renames it
    // to the zone in DNSKEY answers).
    let key_base = work.join("Kdifftest");
    let mut dnssec_block = String::new();
    if dnssec {
        fs::write(
            key_base.with_extension("key"),
            ". IN DNSKEY 257 3 13 0J8u0XJ9GNGFEBXuAmLu04taHG4BXPP3gwhetiOUMnGA+x09nqzgF5IY OyjWB7N3rXqQbnOSILhH1hnuyh7mmA==\n",
        )?;
        fs::write(
            key_base.with_extension("private"),
            "Private-key-format: v1.3\nAlgorithm: 13 (ECDSAP256SHA256)\nPrivateKey: /4BZk8AFvyW5hL3cOLSVxIp1RTqHSAEloWUxj86p3gs=\n",
        )?;
        dnssec_block = format!("    dnssec {{\n        key file {}\n    }}\n", key_base.display());
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
                "{origin}:{port} {{\n    bind 127.0.0.1\n{dnssec_block}    file {}\n}}\n",
                path.display()
            )
        };
        let (cfa, cfb) = (
            work.join(format!("{name}.coredns.conf")),
            work.join(format!("{name}.kerndns.conf")),
        );
        fs::write(&cfa, cf(pa))?;
        fs::write(&cfb, cf(pb))?;
        let a = start(&coredns, &[], &cfa, pa, &work.join(format!("{name}.coredns.log")))?;
        let b = start(&kerndns, &[], &cfb, pb, &work.join(format!("{name}.kerndns.log")))?;
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
        let mut cmd = Command::new(&tool);
        if dnssec {
            cmd.arg("-dnssec-key").arg(key_base.with_extension("key"));
        }
        let out = cmd
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
    let coredns = crate::coredns_ref(&root)?;
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
        let a = start(&coredns, &[], &cfa, pa, &work.join(format!("{name}.coredns.log")))?;
        let b = start(&kerndns, &[], &cfb, pb, &work.join(format!("{name}.kerndns.log")))?;
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

/// One SkyDNS record for the etcd difftest: the name it is stored under,
/// its JSON, and whether it is attached to a lease.
struct EtcdRecord {
    name: String,
    json: String,
    lease: bool,
}

/// The services of CoreDNS's etcd unit tests (each test's set in its own
/// zone), plus weights, leases, TTLs, out-of-zone targets, long TXT
/// strings, IPv4-mapped addresses and broken records.
fn etcd_rich_records() -> Vec<EtcdRecord> {
    let mut v = Vec::new();
    let mut add = |name: &str, json: &str, lease: bool| {
        v.push(EtcdRecord {
            name: name.to_string(),
            json: json.to_string(),
            lease,
        })
    };
    let h = |host: &str| format!(r#"{{"host":"{host}"}}"#);
    let hp = |host: &str, port: u16| format!(r#"{{"host":"{host}","port":{port}}}"#);
    let t = |text: &str| format!(r#"{{"text":"{text}"}}"#);
    let mx = |host: &str, prio: u16| format!(r#"{{"host":"{host}","priority":{prio},"mail":true}}"#);
    let records: Vec<(&str, String)> = vec![
        // lookup_test.go (zone skydns.test. and friends)
        ("a.server1.dev.region1.skydns.test.", hp("dev.server1", 8080)),
        ("a.server1.prod.region1.skydns.test.", hp("10.0.0.1", 8080)),
        ("b.server1.prod.region1.skydns.test.", hp("10.0.0.2", 8080)),
        ("b.server6.prod.region1.skydns.test.", hp("::1", 8080)),
        ("a.txt.server1.prod.region1.skydns.test.", t("sometext")),
        ("b.txt.server1.prod.region1.skydns.test.", t("moretext")),
        ("cname.prod.region1.skydns.test.", h("unresolvable.skydns.test")),
        (
            "priority.skydns.test.",
            r#"{"host":"priority.server1","port":8080,"priority":333}"#.into(),
        ),
        ("a.sub.region1.skydns.test.", h("sub.server1")),
        ("b.sub.region1.skydns.test.", hp("sub.server2", 80)),
        ("c.sub.region1.skydns.test.", hp("10.0.0.1", 8080)),
        (
            "a.targetstrip.skydns.test.",
            r#"{"host":"10.0.0.1","port":8080,"targetstrip":1}"#.into(),
        ),
        ("b.cname.skydns.test.", h("a.cname.skydns.test")),
        ("a.cname.skydns.test.", h("b.cname.skydns.test")),
        ("a.ns.dns.skydns.test.", h("10.0.0.2")),
        ("b.ns.dns.skydns.test.", h("10.0.0.3")),
        (
            "ns1.c.ns.dns.skydns.test.",
            r#"{"host":"10.0.0.4","targetstrip":1}"#.into(),
        ),
        (
            "ns2.c.ns.dns.skydns.test.",
            r#"{"host":"10.0.0.5","targetstrip":1}"#.into(),
        ),
        ("x.skydns_zonea.test.", h("10.0.0.2")),
        ("y.skydns_zonea.test.", h("10.0.0.3")),
        ("x.skydns_zoneb.test.", h("10.0.0.2")),
        ("y.skydns_zoneb.test.", h("10.0.0.3")),
        ("apex.dns.skydns_zoneb.test.", h("10.0.0.4")),
        ("a1.apex.dns.skydns_zoned.test.", h("10.0.0.4")),
        ("a3.apex.dns.skydns_zoned.test.", h("2003::8:1")),
        ("x.skydns_zoned.test.", h("10.0.0.2")),
        ("1.0.0.10.in-addr.arpa.", h("reverse.example.com")),
        ("2.0.0.10.in-addr.arpa.", h("10.0.0.2")),
        // cname_test.go (zone cname.test.)
        ("a.server1.dev.region1.cname.test.", h("cname1.region2.cname.test")),
        ("cname1.region2.cname.test.", h("cname2.region2.cname.test")),
        ("cname2.region2.cname.test.", h("cname3.region2.cname.test")),
        ("cname3.region2.cname.test.", h("cname4.region2.cname.test")),
        ("cname4.region2.cname.test.", h("cname5.region2.cname.test")),
        ("cname5.region2.cname.test.", h("cname6.region2.cname.test")),
        ("cname6.region2.cname.test.", h("endpoint.region2.cname.test")),
        ("endpoint.region2.cname.test.", h("10.240.0.1")),
        ("region2.cname.test.", h("mainendpoint.region2.cname.test")),
        ("cname3.region3.cname.test.", h("cname2.region3.cname.test")),
        ("cname2.region3.cname.test.", h("cname1.region3.cname.test")),
        ("cname1.region3.cname.test.", h("endpoint.region3.cname.test")),
        ("endpoint.region3.cname.test.", t("SOME-RECORD-TEXT")),
        // group_test.go (zone group.test.)
        ("a.dom.group.test.", r#"{"host":"127.0.0.1","group":"g1"}"#.into()),
        ("b.sub.dom.group.test.", r#"{"host":"127.0.0.2","group":"g1"}"#.into()),
        ("a.dom2.group.test.", r#"{"host":"127.0.0.1","group":"g1"}"#.into()),
        ("b.sub.dom2.group.test.", r#"{"host":"127.0.0.2"}"#.into()),
        ("a.dom1.group.test.", r#"{"host":"127.0.0.1","group":"g1"}"#.into()),
        ("b.sub.dom1.group.test.", r#"{"host":"127.0.0.2","group":"g2"}"#.into()),
        ("a.dom3.group.test.", r#"{"text":"foo","group":"g1"}"#.into()),
        ("b.sub.dom3.group.test.", r#"{"text":"bar","group":"g1"}"#.into()),
        // other_test.go (zone other.test.)
        ("a.server1.dev.region1.other.test.", hp("dev.server1", 8080)),
        ("a.mail.other.test.", mx("mx.other.test", 50)),
        ("b.mail.other.test.", mx("mx.example.org", 50)),
        ("a.mx.other.test.", mx("a.ipaddr.other.test", 30)),
        ("a.mx2.other.test.", mx("a.ipaddr.other.test", 0)),
        ("b.mx2.other.test.", mx("b.ipaddr.other.test", 0)),
        ("a.mx3.other.test.", mx("a.ipaddr.other.test", 20)),
        ("b.mx3.other.test.", mx("a.ipaddr.other.test", 30)),
        (
            "c.mx3.other.test.",
            r#"{"host":"172.16.1.9","priority":40,"mail":true,"targetstrip":1}"#.into(),
        ),
        ("mx.other.test.", h("a.ipaddr.other.test")),
        ("a.ipaddr.other.test.", h("172.16.1.1")),
        ("b.ipaddr.other.test.", h("172.16.1.2")),
        ("a1.txt.other.test.", t("abc")),
        ("a2.txt.other.test.", t("abc abc")),
        ("large255.other.test.", t(&"0".repeat(255))),
        ("large400.other.test.", t(&"0".repeat(400))),
        ("large600.other.test.", t(&"1".repeat(600))),
        ("http.multiport.http.other.test.", hp("10.11.11.10", 80)),
        ("https.multiport.http.other.test.", hp("10.11.11.10", 443)),
        // weights within and across priorities, an invalid port
        (
            "a.weights.other.test.",
            r#"{"host":"w1.example.org","port":1,"weight":50}"#.into(),
        ),
        (
            "b.weights.other.test.",
            r#"{"host":"w2.example.org","port":2,"weight":150}"#.into(),
        ),
        ("c.weights.other.test.", r#"{"host":"10.0.9.1","port":3}"#.into()),
        (
            "d.weights.other.test.",
            r#"{"host":"10.0.9.2","port":4,"priority":20,"weight":7}"#.into(),
        ),
        ("e.weights.other.test.", r#"{"host":"10.0.9.3","port":-1}"#.into()),
        // out-of-zone targets, resolved through the server (hosts)
        ("ext.other.test.", h("www.example.org")),
        ("srv.ext.other.test.", hp("www.example.org", 443)),
        ("mapped.other.test.", h("::ffff:10.0.0.9")),
        ("ttl.other.test.", r#"{"host":"10.0.0.10","ttl":60}"#.into()),
        (
            "mixed.case.other.test.",
            r#"{"HOST":"10.0.0.11","Port":53,"unknown":[1,2]}"#.into(),
        ),
        ("null.other.test.", "null".into()),
        ("empty.other.test.", "{}".into()),
        ("x.ns.dns.other.test.", h("ns.example.org")),
        // records that are not valid JSON (zone bad.test.)
        ("broken.bad.test.", "{".into()),
        ("type.bad.test.", r#"{"port":"80"}"#.into()),
        ("ok.bad.test.", h("10.0.0.1")),
    ];
    for (name, json) in records {
        add(name, &json, false);
    }
    // a CNAME chain longer than CoreDNS follows
    for i in 0..14 {
        add(
            &format!("c{i}.long.cname.test."),
            &h(&format!("c{}.long.cname.test", i + 1)),
            false,
        );
    }
    add("c14.long.cname.test.", &h("10.1.1.1"), false);
    // leases: the lease's TTL is clamped (and compared with the service's)
    add("a.lease.other.test.", &h("10.0.8.1"), true);
    add("b.lease.other.test.", r#"{"host":"10.0.8.2","ttl":90}"#, true);
    add("c.lease.other.test.", r#"{"text":"leased"}"#, true);
    v
}

/// Names to ask about: every record's name and its parents up to the
/// zone, wildcard forms of them, names that don't exist, and mixed-case
/// copies; each with every record type the plugin answers (and two it
/// does not).
fn etcd_queries(records: &[EtcdRecord], zones: &[&str], extra: &str) -> String {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for r in records {
        let zone = zones.iter().find(|z| r.name.ends_with(*z)).copied().unwrap_or(".");
        let labels: Vec<&str> = r.name.trim_end_matches('.').split('.').collect();
        let zone_labels = zone.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).count();
        for i in 0..=labels.len().saturating_sub(zone_labels) {
            names.insert(format!("{}.", labels[i..].join(".")));
            if i + 1 < labels.len() {
                // the first label as a wildcard, and the second as `any`
                names.insert(format!("*.{}.", labels[i + 1..].join(".")));
                if i + 2 < labels.len() {
                    names.insert(format!("{}.any.{}.", labels[i], labels[i + 2..].join(".")));
                }
            }
        }
        names.insert(format!("nx.{}", r.name));
    }
    for z in zones {
        for n in [
            String::new(),
            "doesnotexist.".into(),
            "ns.dns.".into(),
            "apex.dns.".into(),
        ] {
            names.insert(format!("{n}{z}"));
        }
    }
    let mixed: Vec<String> = names
        .iter()
        .step_by(5)
        .map(|n| {
            n.chars()
                .enumerate()
                .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c })
                .collect()
        })
        .collect();
    names.extend(mixed);
    let mut q = String::new();
    for n in &names {
        for t in [
            "A", "AAAA", "SRV", "TXT", "MX", "CNAME", "NS", "SOA", "PTR", "HINFO", "AXFR",
        ] {
            q.push_str(&format!("{n} {t}\n"));
        }
    }
    q.push_str(extra);
    q
}

/// `cargo xtask etcd-difftest`: CoreDNS's etcd (Go) and KernDNS's (Rust,
/// or Go through the bridge with `--bridge`) against the same throwaway
/// etcd: the benchmark's 500 services plus [`etcd_rich_records`].
pub fn etcd(args: &[String]) -> Result<()> {
    let mut show = "10".to_string();
    let mut bridge = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--show" => show = it.next().context("--show needs a value")?.clone(),
            "--bridge" => bridge = true,
            other => bail!("unknown argument {other}"),
        }
    }
    let root = root();
    let work = root.join("target/etcd-difftest");
    fs::create_dir_all(&work)?;
    if !Command::new(env!("CARGO"))
        .current_dir(&root)
        .args(["build", "--package", "kerndns"])
        .status()?
        .success()
    {
        bail!("building kerndns failed");
    }
    let kerndns = root.join("target/debug/kerndns");
    let coredns = crate::coredns_ref(&root)?;
    let tool = root.join("target/difftest-tool");
    if !Command::new("go")
        .current_dir(root.join("go/difftest"))
        .args(["build", "-o"])
        .arg(&tool)
        .arg(".")
        .status()?
        .success()
    {
        bail!("building {} failed", tool.display());
    }
    let kerndns_args = if bridge {
        let lib = crate::build_bridge(&root, crate::DEFAULT_BRIDGE_PLUGINS, None)?;
        vec![
            "-bridge".to_string(),
            lib.display().to_string(),
            "-bridge.prefer".into(),
            "etcd".into(),
        ]
    } else {
        Vec::new()
    };

    // etcd with the benchmark's services (zone skydns.local.) and the rest
    let etcd_port = crate::bench::free_port()?;
    let cpus = format!(
        "0-{}",
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) - 1
    );
    let etcd_proc = crate::bench::start_etcd(&work, etcd_port, &cpus, &work)?;
    let grant = crate::bench::etcd_post(etcd_port, "/v3/lease/grant", r#"{"TTL":"7200"}"#)?
        .context("granting a lease failed")?;
    let lease: i64 = grant
        .split("\"ID\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .and_then(|s| s.parse().ok())
        .context("no lease ID in etcd's answer")?;
    let records = etcd_rich_records();
    for r in &records {
        let mut labels: Vec<&str> = r.name.trim_end_matches('.').split('.').collect();
        labels.reverse();
        let key = format!("/skydns/{}", labels.join("/"));
        if !crate::bench::etcd_put(etcd_port, &key, &r.json, if r.lease { lease } else { 0 })? {
            bail!("etcd: writing {key} failed");
        }
    }
    let zones = [
        "skydns.local.",
        "skydns.test.",
        "skydns_zonea.test.",
        "skydns_zoneb.test.",
        "skydns_zoned.test.",
        "cname.test.",
        "group.test.",
        "other.test.",
        "bad.test.",
        "in-addr.arpa.",
    ];
    let bench_queries = fs::read_to_string(work.join("q-etcd.txt"))?;
    let qs = etcd_queries(&records, &zones, &bench_queries);
    let queries = work.join("queries.txt");
    eprintln!("{} query names/types", qs.lines().count());
    fs::write(&queries, qs)?;
    let hosts = work.join("hosts");
    fs::write(
        &hosts,
        "192.0.2.80 www.example.org\n2001:db8::80 www.example.org\n192.0.2.1 w1.example.org\n192.0.2.25 mx.example.org\n",
    )?;

    let z = zones.join(" ");
    let variants = [
        (
            "default",
            format!(
                "etcd {z} {{\n        path /skydns\n        endpoint http://127.0.0.1:{etcd_port}\n        max-lease-ttl 1h\n    }}"
            ),
        ),
        (
            "fallthrough",
            format!(
                "etcd {z} {{\n        endpoint 127.0.0.1:{etcd_port}\n        fallthrough other.test in-addr.arpa\n        no_apex_fallback\n        min-lease-ttl 2h30m\n        max-lease-ttl 24h\n    }}"
            ),
        ),
    ];
    let mut total_diffs = 0;
    let mut summary = Vec::new();
    for (name, etcd_block) in &variants {
        let (pa, pb) = two_ports()?;
        let cf = |port: u16| {
            format!(
                ".:{port} {{\n    bind 127.0.0.1\n    {etcd_block}\n    hosts {} {{\n        fallthrough\n    }}\n}}\n",
                hosts.display()
            )
        };
        let (cfa, cfb) = (
            work.join(format!("{name}.coredns.conf")),
            work.join(format!("{name}.kerndns.conf")),
        );
        fs::write(&cfa, cf(pa))?;
        fs::write(&cfb, cf(pb))?;
        let a = start(&coredns, &[], &cfa, pa, &work.join(format!("{name}.coredns.log")))?;
        let b = start(
            &kerndns,
            &kerndns_args,
            &cfb,
            pb,
            &work.join(format!("{name}.kerndns.log")),
        )?;
        if a.is_none() || b.is_none() {
            bail!("{name}: a server failed to start (see {})", work.display());
        }
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
    println!(
        "\nvariants (KernDNS with the {} etcd plugin):",
        if bridge { "Go (bridged)" } else { "Rust" }
    );
    for s in &summary {
        println!("{s}");
    }
    if total_diffs > 0 {
        println!("\n{total_diffs} differences");
        // process::exit skips destructors: stop etcd first
        drop(etcd_proc);
        std::process::exit(1);
    }
    println!("\nno differences");
    Ok(())
}
