//! Project automation: `cargo xtask <command>`.
//!
//! compat-test   Run CoreDNS's integration tests (third_party/coredns/test)
//!               against the kerndns binary and compare with
//!               go/compat/expectations.txt.
//! build-bridge  Build the Go bridge library (go/bridge) with a list of
//!               CoreDNS plugins: target/bridge/libkerndns_bridge.so.
//! difftest      Serve the same zones from CoreDNS and kerndns and diff the
//!               answers to generated queries (see go/difftest).
//! bench         Benchmark CoreDNS vs kerndns per scenario with dnsperf
//!               (bench/plugins: one directory per plugin; bench/setups);
//!               --check: every registered plugin has a scenario.
//! loadgen       DNS load generator for DoQ, DoH3 and gRPC with dnsperf's
//!               arguments and output (bench uses it for -m doq|doh3|grpc).
//! k8s-cases     Regenerate crates/kubernetes/testdata/upstream_cases.json by
//!               running CoreDNS's kubernetes handler test suites in Go.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

mod bench;
mod difftest;
mod fakeapi;
mod loadgen;

const USAGE: &str =
    "usage: cargo xtask compat-test [--release] [--run REGEX] [--update] [--target coredns] [--bridge [LIB]]
       cargo xtask build-bridge [--plugins etcd,whoami,...] [--out PATH]
       cargo xtask difftest [--release] [--zone NAME] [--show N] [--dnssec]
       cargo xtask bench [--level 2,3] [--plugin NAME,...] [--scenario CASE,...] [--duration SECONDS] [--runs N] [--coredns PATH] [--kubeconfig PATH] [--list]
       cargo xtask bench --check
       cargo xtask loadgen -m doq|doh3|grpc -p PORT -d QUERYFILE [-s IP] [-c CLIENTS] [-T THREADS] [-q OUTSTANDING] [-l SECONDS] [-Q QPS] [-t TIMEOUT] [--ca PEM] [--tls]
       cargo xtask k8s-cases
       cargo xtask k8s-difftest [--context KUBECONTEXT] [--show N]
       cargo xtask k8s-bench [--sizes 1000,10000,50000] [--duration SECONDS] [--coredns PATH]

  --release         build and test the release binary
  --run REGEX       only run upstream tests matching REGEX
  --update          rewrite go/compat/expectations.txt from this run
  --target coredns  run the tests against in-process CoreDNS instead (checks the harness)";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("compat-test") => compat_test(&args[1..]),
        Some("build-bridge") => build_bridge_cmd(&args[1..]),
        Some("difftest") => difftest::run(&args[1..]),
        Some("bench") => bench::run(&args[1..]),
        Some("loadgen") => loadgen::run(&args[1..]),
        Some("k8s-cases") => k8s_cases(),
        Some("k8s-difftest") => difftest::k8s(&args[1..]),
        Some("k8s-bench") => bench::k8s(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}

pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Xfail,
    Skip,
}

impl Status {
    fn parse(s: &str) -> Option<Status> {
        match s {
            "pass" => Some(Status::Pass),
            "xfail" => Some(Status::Xfail),
            "skip" => Some(Status::Skip),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Xfail => "xfail",
            Status::Skip => "skip",
        }
    }
}

/// `go/compat/expectations.txt`: `<status> <TestName> [reason...]` per line.
fn read_expectations(path: &Path) -> Result<BTreeMap<String, (Status, String)>> {
    let mut out = BTreeMap::new();
    let Ok(text) = fs::read_to_string(path) else {
        return Ok(out);
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(st), Some(name)) = (words.next(), words.next()) else {
            bail!("{}:{}: expected '<status> <test> [reason]'", path.display(), n + 1);
        };
        let Some(st) = Status::parse(st) else {
            bail!(
                "{}:{}: unknown status {st:?} (pass, xfail or skip)",
                path.display(),
                n + 1
            );
        };
        let reason = words.collect::<Vec<_>>().join(" ");
        out.insert(name.to_string(), (st, reason));
    }
    Ok(out)
}

fn write_expectations(path: &Path, exp: &BTreeMap<String, (Status, String)>) -> Result<()> {
    let mut s = String::from(
        "# Expected results of CoreDNS's integration tests (third_party/coredns/test) against KernDNS.\n\
         # Maintained by `cargo xtask compat-test --update`; edit reasons by hand.\n\
         #\n\
         #   pass   must pass\n\
         #   xfail  fails today; the run fails if it starts passing, so it gets promoted\n\
         #   skip   not run: tests Go internals, or never starts a server through the helpers\n\
         #\n\
         # <status> <test> <reason>\n",
    );
    let width = exp.keys().map(String::len).max().unwrap_or(0);
    for (name, (st, reason)) in exp {
        let line = format!("{:<5} {:<width$} {}", st.as_str(), name, reason);
        s.push_str(line.trim_end());
        s.push('\n');
    }
    fs::write(path, s)?;
    Ok(())
}

#[derive(Debug, Default)]
struct TestRun {
    action: Option<String>,
    first_error: Option<String>,
}

fn compat_test(args: &[String]) -> Result<()> {
    let mut release = false;
    let mut run: Option<String> = None;
    let mut update = false;
    let mut target_coredns = false;
    let mut bridge: Option<Option<PathBuf>> = None;
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--release" => release = true,
            "--run" => run = Some(it.next().context("--run needs a value")?.clone()),
            "--update" => update = true,
            "--bridge" => {
                let path = it.next_if(|a| !a.starts_with("--")).map(PathBuf::from);
                bridge = Some(path);
            }
            "--target" => match it.next().map(String::as_str) {
                Some("coredns") => target_coredns = true,
                Some("kerndns") => target_coredns = false,
                other => bail!("unknown target {other:?}"),
            },
            other => bail!("unknown argument {other}\n{USAGE}"),
        }
    }

    let root = root();
    let upstream = root.join("third_party/coredns");
    if !upstream.join("test/server.go").exists() {
        bail!("third_party/coredns is missing; run `git submodule update --init`");
    }

    // 1. build kerndns
    let mut build = Command::new(env!("CARGO"));
    build.current_dir(&root).args(["build", "--package", "kerndns"]);
    if release {
        build.arg("--release");
    }
    if !build.status()?.success() {
        bail!("building kerndns failed");
    }
    let bin = root
        .join("target")
        .join(if release { "release" } else { "debug" })
        .join("kerndns");

    // --bridge: CoreDNS's etcd tests (build tag `etcd`) with the Go etcd
    // plugin running inside kerndns through the bridge, against a local etcd
    let bridge_lib = match &bridge {
        None => None,
        Some(Some(p)) => Some(p.clone()),
        Some(None) => Some(build_bridge(&root, DEFAULT_BRIDGE_PLUGINS, None)?),
    };
    let etcd_guard = match bridge_lib {
        Some(_) => Some(EtcdGuard::start(&root.join("target/compat"))?),
        None => None,
    };
    let run = match (&bridge_lib, run) {
        (Some(_), None) => Some("Etcd".to_string()),
        (_, r) => r,
    };

    // 2. overlay: our helpers replace test/server.go and add kerndns_compat.go
    let work = root.join("target/compat");
    fs::create_dir_all(&work)?;
    let overlay = work.join("overlay.json");
    let overlay_json = serde_json::json!({
        "Replace": {
            upstream.join("test/server.go").to_string_lossy(): root.join("go/compat/server.go").to_string_lossy(),
            upstream.join("test/kerndns_compat.go").to_string_lossy(): root.join("go/compat/kerndns_compat.go").to_string_lossy(),
        }
    });
    fs::write(&overlay, serde_json::to_vec_pretty(&overlay_json)?)?;
    let trace = work.join("trace.txt");
    let _ = fs::remove_file(&trace);

    let exp_path = root.join(if bridge_lib.is_some() {
        "go/compat/expectations-bridge.txt"
    } else {
        "go/compat/expectations.txt"
    });
    let exp_name = exp_path.strip_prefix(&root).unwrap_or(&exp_path).display().to_string();
    let expectations = read_expectations(&exp_path)?;
    let skips: Vec<&str> = expectations
        .iter()
        .filter(|(_, (st, _))| *st == Status::Skip)
        .map(|(n, _)| n.as_str())
        .collect();

    // 3. compile the upstream test package once, then run every test in its
    //    own process: a panic in one test (e.g. calling Stop on the nil
    //    instance a failed start returns) must not hide the others.
    let test_bin = work.join(if bridge_lib.is_some() {
        "coredns-test-etcd.test"
    } else {
        "coredns-test.test"
    });
    let st = Command::new("go")
        .current_dir(&upstream)
        .args(["test", "-c", "-overlay"])
        .arg(&overlay)
        .args(if bridge_lib.is_some() {
            &["-tags", "etcd"][..]
        } else {
            &[][..]
        })
        .arg("-o")
        .arg(&test_bin)
        .arg("./test/")
        .status()
        .context("running `go test -c` (is Go installed?)")?;
    if !st.success() {
        bail!("compiling the CoreDNS test package failed");
    }
    let pkg_dir = upstream.join("test");
    let listing = Command::new(&test_bin)
        .current_dir(&pkg_dir)
        .arg("-test.list")
        .arg(run.as_deref().unwrap_or(".*"))
        .output()?;
    let names: Vec<String> = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter(|l| l.starts_with("Test"))
        .filter(|l| target_coredns || !skips.contains(l))
        .map(String::from)
        .collect();
    if names.is_empty() {
        bail!("no upstream tests matched");
    }
    eprintln!(
        "running {} CoreDNS integration tests against {} ...",
        names.len(),
        if target_coredns {
            "in-process CoreDNS"
        } else {
            "kerndns"
        }
    );

    let mut tests: BTreeMap<String, TestRun> = BTreeMap::new();
    for name in &names {
        let mut cmd = Command::new("go");
        cmd.current_dir(&pkg_dir)
            .args(["tool", "test2json", "-t", "-p", "test"])
            .arg(&test_bin)
            .args(["-test.v=test2json", "-test.count=1", "-test.timeout=5m"])
            .arg(format!("-test.run=^{name}$"))
            .env("KERNDNS_BIN", &bin)
            .env("KERNDNS_COMPAT_TRACE", &trace)
            .env("KERNDNS_BRIDGE", bridge_lib.as_deref().unwrap_or(Path::new("")))
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if target_coredns {
            cmd.env("KERNDNS_COMPAT_TARGET", "coredns");
        }
        let mut child = cmd.spawn().context("running go tool test2json")?;
        for line in BufReader::new(child.stdout.take().unwrap()).lines() {
            let line = line?;
            let Ok(ev) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            let Some(test) = ev.get("Test").and_then(|t| t.as_str()) else {
                // output outside a test, e.g. a panic that killed the binary
                let out = ev.get("Output").and_then(|o| o.as_str()).unwrap_or("");
                let entry = tests.entry(name.clone()).or_default();
                if out.starts_with("panic:") && entry.first_error.is_none() {
                    entry.first_error = Some(out.trim().chars().take(160).collect());
                }
                continue;
            };
            if let Some((parent, _)) = test.split_once('/') {
                // a subtest: its first error explains the parent's failure
                let entry = tests.entry(parent.to_string()).or_default();
                if ev.get("Action").and_then(|a| a.as_str()) == Some("output") && entry.first_error.is_none() {
                    let out = ev.get("Output").and_then(|o| o.as_str()).unwrap_or("");
                    entry.first_error = test_error(out);
                }
                continue;
            }
            let entry = tests.entry(test.to_string()).or_default();
            match ev.get("Action").and_then(|a| a.as_str()) {
                Some(a @ ("pass" | "fail" | "skip")) => entry.action = Some(a.to_string()),
                Some("output") => {
                    let out = ev.get("Output").and_then(|o| o.as_str()).unwrap_or("");
                    if entry.first_error.is_none()
                        && let Some(msg) = test_error(out)
                    {
                        entry.first_error = Some(msg);
                    }
                }
                _ => {}
            }
        }
        child.wait()?;
        let t = tests.entry(name.clone()).or_default();
        let mark = match t.action.as_deref() {
            Some("pass") => ".",
            Some("skip") => "s",
            _ => "F",
        };
        eprint!("{mark}");
    }
    eprintln!();

    if target_coredns {
        let pass = tests.values().filter(|t| t.action.as_deref() == Some("pass")).count();
        println!("in-process CoreDNS: {pass}/{} tests passed", tests.len());
        for (name, t) in &tests {
            if t.action.as_deref() == Some("fail") {
                println!("  FAIL {name}: {}", t.first_error.as_deref().unwrap_or(""));
            }
        }
        return Ok(());
    }

    let used: BTreeSet<String> = fs::read_to_string(&trace)
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect();

    // 4. compare
    let mut new_exp = expectations.clone();
    let mut regressions = Vec::new();
    let mut fixed = Vec::new();
    let mut unclassified = Vec::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (name, t) in &tests {
        let action = t.action.as_deref().unwrap_or("fail");
        let exercised = used.contains(name);
        let (actual, reason) = match (action, exercised) {
            ("pass", true) => (Status::Pass, String::new()),
            ("pass", false) | ("skip", _) => (
                Status::Skip,
                "does not start a server through the test helpers".to_string(),
            ),
            _ => (Status::Xfail, t.first_error.clone().unwrap_or_else(|| "failed".into())),
        };
        *counts.entry(actual.as_str()).or_default() += 1;
        match expectations.get(name) {
            None => unclassified.push((name.clone(), actual, reason.clone())),
            Some((Status::Pass, _)) if actual != Status::Pass => regressions.push((name.clone(), reason.clone())),
            Some((Status::Xfail, _)) if actual == Status::Pass => fixed.push(name.clone()),
            _ => {}
        }
        // hand-written skip reasons are kept; xfail reasons always show the latest failure
        let keep_reason =
            matches!(expectations.get(name), Some((st, r)) if *st == actual && *st == Status::Skip && !r.is_empty());
        if !keep_reason {
            new_exp.insert(name.clone(), (actual, reason));
        }
    }
    let skipped = expectations.values().filter(|(st, _)| *st == Status::Skip).count();

    println!();
    println!(
        "CoreDNS integration tests against KernDNS ({} run, {} skipped by expectations):",
        tests.len(),
        skipped
    );
    println!("  pass   {}", counts.get("pass").unwrap_or(&0));
    println!("  xfail  {}", counts.get("xfail").unwrap_or(&0));
    println!("  skip   {} (did not start KernDNS)", counts.get("skip").unwrap_or(&0));

    if update {
        if run.is_some() {
            // a filtered run only updates the tests it ran
            println!("updating the {} tests that ran", tests.len());
        }
        write_expectations(&exp_path, &new_exp)?;
        println!("wrote {}", exp_path.display());
        return Ok(());
    }

    let mut failed = false;
    if !regressions.is_empty() {
        failed = true;
        println!("\nREGRESSIONS (expected pass):");
        for (n, r) in &regressions {
            println!("  {n}: {r}");
        }
    }
    if !fixed.is_empty() {
        failed = true;
        println!("\nNOW PASSING (promote to pass in go/compat/expectations.txt, or run with --update):");
        for n in &fixed {
            println!("  {n}");
        }
    }
    if !unclassified.is_empty() {
        failed = true;
        println!("\nNOT IN {exp_name} (run with --update to add them):");
        for (n, st, r) in &unclassified {
            println!("  {:<5} {n} {r}", st.as_str());
        }
    }
    if failed {
        // process::exit skips destructors: stop etcd first
        drop(etcd_guard);
        std::process::exit(1);
    }
    drop(etcd_guard);
    println!("\nall results match {}", exp_name);
    Ok(())
}

/// The message of a `t.Fatalf`/`t.Errorf` line: `    file_test.go:12: msg`.
fn test_error(out: &str) -> Option<String> {
    let line = out.trim();
    let (loc, msg) = line.split_once(": ")?;
    if !loc.contains("_test.go:") {
        return None;
    }
    let msg = msg.trim();
    let msg: String = msg.chars().take(160).collect();
    Some(msg.replace('\n', " "))
}

/// Run CoreDNS's kubernetes handler suites against the Go plugin (via an
/// overlay test file) and dump queries, fake API data and responses.
fn k8s_cases() -> Result<()> {
    let root = root();
    let upstream = root.join("third_party/coredns");
    let work = root.join("target");
    fs::create_dir_all(&work)?;
    let overlay = work.join("k8s-overlay.json");
    let json = serde_json::json!({
        "Replace": {
            upstream.join("plugin/kubernetes/kerndns_dump_test.go").to_string_lossy():
                root.join("go/k8sdump/kerndns_dump_test.go").to_string_lossy(),
        }
    });
    fs::write(&overlay, serde_json::to_vec_pretty(&json)?)?;
    let out = root.join("crates/kubernetes/testdata/upstream_cases.json");
    let st = Command::new("go")
        .current_dir(&upstream)
        .args(["test", "-count=1", "-run", "TestKernDNSDump", "-overlay"])
        .arg(&overlay)
        .arg("./plugin/kubernetes/")
        .env("KERNDNS_K8S_DUMP", &out)
        .status()?;
    if !st.success() {
        bail!("go test failed");
    }
    println!("wrote {}", out.display());
    Ok(())
}

/// Plugins in the bridge `compat-test --bridge` and the benchmarks build.
const DEFAULT_BRIDGE_PLUGINS: &str = "etcd,whoami";

/// `cargo xtask build-bridge`: generate go/bridge/plugins_gen.go and build
/// the c-shared library. In-tree plugin names become CoreDNS import paths;
/// anything with a `/` is used as an import path as is (third-party).
fn build_bridge(root: &Path, plugins: &str, out: Option<PathBuf>) -> Result<PathBuf> {
    let mut src =
        String::from("// Code generated by `cargo xtask build-bridge`; DO NOT EDIT.\n\npackage main\n\nimport (\n");
    for p in plugins.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let path = if p.contains('/') {
            p.to_string()
        } else {
            format!("github.com/coredns/coredns/plugin/{p}")
        };
        src.push_str(&format!("\t_ \"{path}\"\n"));
    }
    src.push_str(")\n");
    let dir = root.join("go/bridge");
    fs::write(dir.join("plugins_gen.go"), src)?;
    let out = out.unwrap_or_else(|| root.join("target/bridge/libkerndns_bridge.so"));
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    eprintln!("building the Go bridge with {plugins} ...");
    let st = Command::new("go")
        .current_dir(&dir)
        .env("GOFLAGS", "-mod=mod")
        .args(["build", "-buildmode=c-shared", "-o"])
        .arg(&out)
        .arg(".")
        .status()
        .context("running `go build` (is Go installed, with cgo and a C compiler?)")?;
    if !st.success() {
        bail!("building the Go bridge failed");
    }
    Ok(out)
}

fn build_bridge_cmd(args: &[String]) -> Result<()> {
    let mut plugins = DEFAULT_BRIDGE_PLUGINS.to_string();
    let mut out = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--plugins" => plugins = it.next().context("--plugins needs a list")?.clone(),
            "--out" => out = Some(PathBuf::from(it.next().context("--out needs a path")?)),
            other => bail!("unknown argument {other}\n{USAGE}"),
        }
    }
    let p = build_bridge(&root(), &plugins, out)?;
    println!("{}", p.display());
    Ok(())
}

/// A throwaway etcd on 127.0.0.1:2379 for the upstream etcd tests, unless
/// one already listens there.
struct EtcdGuard(Option<std::process::Child>);

impl EtcdGuard {
    fn start(work: &Path) -> Result<EtcdGuard> {
        if std::net::TcpStream::connect("127.0.0.1:2379").is_ok() {
            eprintln!("using the etcd already listening on 127.0.0.1:2379");
            return Ok(EtcdGuard(None));
        }
        let data = work.join("etcd-data");
        let _ = fs::remove_dir_all(&data);
        let child = Command::new("etcd")
            .args(["--data-dir"])
            .arg(&data)
            .args([
                "--listen-client-urls",
                "http://127.0.0.1:2379",
                "--advertise-client-urls",
                "http://127.0.0.1:2379",
                "--listen-peer-urls",
                "http://127.0.0.1:2380",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("starting etcd (is it installed?)")?;
        for _ in 0..100 {
            if std::net::TcpStream::connect("127.0.0.1:2379").is_ok() {
                return Ok(EtcdGuard(Some(child)));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        bail!("etcd did not start listening on 127.0.0.1:2379")
    }
}

impl Drop for EtcdGuard {
    fn drop(&mut self) {
        if let Some(c) = self.0.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
