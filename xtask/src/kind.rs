//! `cargo xtask kind-test`: CoreDNS's end-to-end Kubernetes tests
//! (github.com/coredns/ci, `test/kubernetes`) against the cluster DNS of
//! the current kubeconfig's cluster, set up the way coredns/ci sets it up
//! (see the `kind` job in .github/workflows/ci.yml).
//!
//! Like `compat-test`, the test package is compiled once and every test
//! runs in its own process, so a panic in one test doesn't hide the
//! others, and the results are compared with
//! `go/compat/expectations-kind.txt`. With `--target coredns` the cluster
//! runs CoreDNS's own image and the results are only reported: that run
//! checks the harness and the environment.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::{Status, TestRun, read_expectations, root, test_error, write_expectations};

const HEADER: &str = "# Expected results of CoreDNS's end-to-end Kubernetes tests (github.com/coredns/ci,\n\
     # test/kubernetes) with KernDNS as the cluster DNS of a kind cluster (CI job `kind`).\n\
     # Maintained by `cargo xtask kind-test --update`; edit reasons by hand.\n\
     #\n\
     #   pass   must pass\n\
     #   xfail  fails today; the run fails if it starts passing, so it gets promoted\n\
     #   skip   result ignored: the test doesn't exercise the cluster DNS\n\
     #\n\
     # <status> <test> <reason>\n";

pub fn run(args: &[String]) -> Result<()> {
    let mut ci_dir: Option<PathBuf> = None;
    let mut target_coredns = false;
    let mut update = false;
    let mut filter: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--ci-dir" => ci_dir = Some(PathBuf::from(it.next().context("--ci-dir needs a path")?)),
            "--target" => match it.next().map(String::as_str) {
                Some("coredns") => target_coredns = true,
                Some("kerndns") => target_coredns = false,
                other => bail!("--target: kerndns or coredns, not {other:?}"),
            },
            "--run" => filter = Some(it.next().context("--run needs a regex")?.clone()),
            "--update" => update = true,
            other => bail!("unknown argument {other}"),
        }
    }
    let ci_dir = ci_dir.context("--ci-dir: a coredns/ci checkout (with ../coredns next to it)")?;
    let pkg_dir = ci_dir.join("test/kubernetes");
    let exp_path = root().join("go/compat/expectations-kind.txt");
    let expectations = read_expectations(&exp_path)?;

    let test_bin = std::env::temp_dir().join("coredns-ci-kubernetes.test");
    let st = Command::new("go")
        .current_dir(&pkg_dir)
        .args(["test", "-c", "-o"])
        .arg(&test_bin)
        .arg(".")
        .status()
        .context("running `go test -c` (is Go installed?)")?;
    if !st.success() {
        bail!("compiling coredns/ci's test/kubernetes failed");
    }
    let listing = Command::new(&test_bin)
        .current_dir(&pkg_dir)
        .arg("-test.list")
        .arg(filter.as_deref().unwrap_or(".*"))
        .output()?;
    let names: Vec<String> = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter(|l| l.starts_with("Test"))
        .map(String::from)
        .collect();
    if names.is_empty() {
        bail!("no tests matched");
    }
    let target = if target_coredns { "CoreDNS" } else { "KernDNS" };
    eprintln!(
        "running {} coredns/ci kubernetes tests against {target} ...",
        names.len()
    );

    let mut tests: BTreeMap<String, TestRun> = BTreeMap::new();
    for name in &names {
        eprintln!("=== {name}");
        let mut child = Command::new("go")
            .current_dir(&pkg_dir)
            .args(["tool", "test2json", "-t", "-p", "kubernetes"])
            .arg(&test_bin)
            .args(["-test.v=test2json", "-test.count=1", "-test.timeout=10m"])
            .arg(format!("-test.run=^{name}$"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("running go tool test2json")?;
        for line in BufReader::new(child.stdout.take().unwrap()).lines() {
            let line = line?;
            let Ok(ev) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            let action = ev.get("Action").and_then(|a| a.as_str());
            let out = ev.get("Output").and_then(|o| o.as_str()).unwrap_or("");
            if action == Some("output") {
                // the whole log, for the CI job output
                eprint!("{out}");
            }
            let test = ev.get("Test").and_then(|t| t.as_str()).unwrap_or(name);
            let parent = test.split_once('/').map_or(test, |(p, _)| p);
            let entry = tests.entry(parent.to_string()).or_default();
            match action {
                Some(a @ ("pass" | "fail" | "skip")) if test == parent => entry.action = Some(a.to_string()),
                Some("output") if entry.first_error.is_none() => {
                    entry.first_error = if out.starts_with("panic:") {
                        Some(out.trim().chars().take(160).collect())
                    } else {
                        test_error(out)
                    };
                }
                _ => {}
            }
        }
        child.wait()?;
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut new_exp = expectations.clone();
    let mut regressions = Vec::new();
    let mut fixed = Vec::new();
    let mut unclassified = Vec::new();
    println!("\ncoredns/ci test/kubernetes against {target}:");
    for (name, t) in &tests {
        let passed = t.action.as_deref() == Some("pass");
        let reason = if passed {
            String::new()
        } else {
            t.first_error.clone().unwrap_or_else(|| "failed".into())
        };
        println!("  {:<5} {name} {reason}", if passed { "PASS" } else { "FAIL" });
        if target_coredns {
            continue;
        }
        let actual = if passed { Status::Pass } else { Status::Xfail };
        *counts.entry(actual.as_str()).or_default() += 1;
        match expectations.get(name) {
            Some((Status::Skip, _)) => continue,
            None => unclassified.push((name.clone(), actual, reason.clone())),
            Some((Status::Pass, _)) if !passed => regressions.push((name.clone(), reason.clone())),
            Some((Status::Xfail, _)) if passed => fixed.push(name.clone()),
            _ => {}
        }
        // hand-written xfail reasons are kept while the test still fails
        let keep = matches!(expectations.get(name), Some((st, r)) if *st == actual && !r.is_empty());
        if !keep {
            new_exp.insert(name.clone(), (actual, reason));
        }
    }
    if target_coredns {
        let pass = tests.values().filter(|t| t.action.as_deref() == Some("pass")).count();
        println!("CoreDNS: {pass}/{} tests passed", tests.len());
        return Ok(());
    }
    println!(
        "pass {}, xfail {}",
        counts.get("pass").unwrap_or(&0),
        counts.get("xfail").unwrap_or(&0)
    );
    if update {
        write_expectations(&exp_path, &new_exp, HEADER)?;
        println!("wrote {}", exp_path.display());
        return Ok(());
    }
    let mut failed = false;
    for (title, list) in [
        (
            "REGRESSIONS (expected pass)",
            regressions.iter().map(|(n, r)| format!("{n}: {r}")).collect::<Vec<_>>(),
        ),
        ("NOW PASSING (promote to pass, or run with --update)", fixed.clone()),
        (
            "NOT IN go/compat/expectations-kind.txt (run with --update to add them)",
            unclassified
                .iter()
                .map(|(n, st, r)| format!("{:<5} {n} {r}", st.as_str()))
                .collect(),
        ),
    ] {
        if !list.is_empty() {
            failed = true;
            println!("\n{title}:");
            for l in list {
                println!("  {l}");
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
    Ok(())
}
