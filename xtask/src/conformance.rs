//! `cargo xtask k8s-conformance`: Kubernetes' own `[sig-network] DNS`
//! end-to-end tests (kubernetes/kubernetes test/e2e/network/dns*.go, the
//! `[Conformance]` ones and the rest that run on kind) against the cluster
//! DNS of the current kubeconfig's cluster (CI job `k8s-conformance`).
//!
//! The tests run from the prebuilt `e2e.test` and `ginkgo` of the
//! Kubernetes release (kubernetes-test-linux-amd64.tar.gz) matching the
//! cluster's version, in parallel, with a ginkgo JSON report. The report is
//! compared with `go/compat/expectations-conformance.txt`. With
//! `--target coredns` the cluster runs CoreDNS's own image and the results
//! are only reported: that run checks the harness and the environment.
//! `--report FILE` compares an existing report without running anything.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::{Status, root};

/// The tests that run: every spec whose full text contains one of these
/// (ginkgo `--focus`)...
const FOCUS: &[&str] = &[
    "[sig-network] DNS ",
    "[sig-network] Networking should provider Internet connection for containers using DNS",
];

/// ...and none of these (ginkgo `--skip`), each with the reason.
const SKIP: &[(&str, &str)] = &[
    (
        "[Provider:gce]",
        "needs a GCE cluster (skipped by the e2e framework anyway)",
    ),
    (
        "[Feature:PerformanceDNS]",
        "a capacity test (the maximum number of Services, minutes of setup), not a behaviour check",
    ),
];

const HEADER: &str = "# Expected results of Kubernetes' [sig-network] DNS end-to-end tests (e2e.test of the\n\
     # Kubernetes release matching kind's node image) with KernDNS as the cluster DNS of a kind\n\
     # cluster (CI job `k8s-conformance`). Maintained by `cargo xtask k8s-conformance --update`;\n\
     # edit reasons by hand.\n\
     #\n\
     #   pass   must pass\n\
     #   xfail  fails today; the run fails if it starts passing, so it gets promoted\n\
     #   skip   result ignored\n\
     #\n\
     # <status> <full ginkgo spec text> [# reason]\n";

#[derive(Debug)]
struct Outcome {
    /// ginkgo's state: passed, failed, skipped, panicked, timedout, ...
    state: String,
    message: String,
    seconds: f64,
}

pub fn run(args: &[String]) -> Result<()> {
    let mut e2e_dir: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;
    let mut target_coredns = false;
    let mut update = false;
    let mut nodes = 4usize;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--e2e-dir" => e2e_dir = Some(PathBuf::from(it.next().context("--e2e-dir needs a path")?)),
            "--report" => report = Some(PathBuf::from(it.next().context("--report needs a path")?)),
            "--nodes" => nodes = it.next().context("--nodes needs a number")?.parse()?,
            "--target" => match it.next().map(String::as_str) {
                Some("coredns") => target_coredns = true,
                Some("kerndns") => target_coredns = false,
                other => bail!("--target: kerndns or coredns, not {other:?}"),
            },
            "--update" => update = true,
            other => bail!("unknown argument {other}"),
        }
    }
    let target = if target_coredns { "CoreDNS" } else { "KernDNS" };
    let report = match (report, e2e_dir) {
        (Some(r), _) => r,
        (None, Some(dir)) => run_e2e(&dir, nodes, target)?,
        (None, None) => bail!(
            "--e2e-dir: the kubernetes/test/bin directory of kubernetes-test-linux-amd64.tar.gz \
             (or --report FILE)"
        ),
    };
    let results = parse_report(&report)?;
    compare(&results, target_coredns, update)
}

/// ginkgo's regex for a list of literal strings.
fn alternation<'a>(items: impl Iterator<Item = &'a str>) -> String {
    items
        .map(|s| {
            s.chars().fold(String::new(), |mut out, c| {
                if "\\.+*?()|[]{}^$".contains(c) {
                    out.push('\\');
                }
                out.push(c);
                out
            })
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn selected(name: &str) -> bool {
    FOCUS.iter().any(|f| name.contains(f)) && !SKIP.iter().any(|(s, _)| name.contains(s))
}

/// Runs the focused suite with `ginkgo --nodes N e2e.test`; returns the
/// JSON report's path. `[Serial]` specs run after the others, alone.
fn run_e2e(dir: &Path, nodes: usize, target: &str) -> Result<PathBuf> {
    let out = root().join("target/k8s-conformance");
    fs::create_dir_all(&out)?;
    let report = out.join("report.json");
    let _ = fs::remove_file(&report);
    let kubeconfig = std::env::var("KUBECONFIG")
        .ok()
        .filter(|k| !k.is_empty())
        .or_else(|| std::env::var("HOME").ok().map(|h| format!("{h}/.kube/config")))
        .context("no KUBECONFIG and no HOME")?;
    eprintln!("running Kubernetes' [sig-network] DNS e2e tests against {target} ...");
    let start = std::time::Instant::now();
    let st = Command::new(dir.join("ginkgo"))
        .arg(format!("--nodes={nodes}"))
        .arg(format!("--focus={}", alternation(FOCUS.iter().copied())))
        .arg(format!("--skip={}", alternation(SKIP.iter().map(|(s, _)| *s))))
        .args(["--timeout=60m", "--no-color", "--json-report=report.json"])
        .arg(format!("--output-dir={}", out.display()))
        .arg(dir.join("e2e.test"))
        .arg("--")
        .arg(format!("--kubeconfig={kubeconfig}"))
        .args(["--provider=skeleton", "--disable-log-dump"])
        .arg(format!("--report-dir={}", out.display()))
        .status()
        .context("running ginkgo")?;
    eprintln!("ginkgo exited with {st} after {:.0} s", start.elapsed().as_secs_f64());
    if !report.exists() {
        bail!("ginkgo wrote no report at {}", report.display());
    }
    Ok(report)
}

fn parse_report(path: &Path) -> Result<BTreeMap<String, Outcome>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let suites: serde_json::Value = serde_json::from_str(&text).context("parsing the ginkgo JSON report")?;
    let mut out = BTreeMap::new();
    let mut suite_failures = Vec::new();
    for suite in suites.as_array().context("report: expected an array of suites")? {
        for spec in suite["SpecReports"].as_array().into_iter().flatten() {
            let state = spec["State"].as_str().unwrap_or("").to_string();
            let message = spec["Failure"]["Message"]
                .as_str()
                .unwrap_or("")
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("")
                .chars()
                .take(200)
                .collect::<String>();
            let leaf = spec["LeafNodeType"].as_str().unwrap_or("");
            if leaf != "It" {
                // suite setup and reporting nodes: a failure there breaks the run
                if !matches!(state.as_str(), "passed" | "skipped") {
                    suite_failures.push(format!("{leaf} {state}: {message}"));
                }
                continue;
            }
            let mut parts: Vec<&str> = spec["ContainerHierarchyTexts"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|t| t.as_str())
                .collect();
            parts.push(spec["LeafNodeText"].as_str().unwrap_or(""));
            let name = parts.join(" ");
            if !selected(&name) {
                continue;
            }
            let seconds = spec["RunTime"].as_f64().unwrap_or(0.0) / 1e9;
            out.insert(
                name,
                Outcome {
                    state,
                    message,
                    seconds,
                },
            );
        }
    }
    if !suite_failures.is_empty() {
        for f in &suite_failures {
            println!("SUITE {f}");
        }
        bail!("the e2e suite itself failed (see above)");
    }
    if out.is_empty() {
        bail!("no [sig-network] DNS specs in {}", path.display());
    }
    Ok(out)
}

/// `<status> <name> [# reason]` per line; names contain spaces.
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
        let (st, rest) = line
            .split_once(char::is_whitespace)
            .with_context(|| format!("{}:{}: expected '<status> <test> [# reason]'", path.display(), n + 1))?;
        let st = Status::parse(st).with_context(|| {
            format!(
                "{}:{}: unknown status {st:?} (pass, xfail or skip)",
                path.display(),
                n + 1
            )
        })?;
        let (name, reason) = rest.split_once(" # ").unwrap_or((rest, ""));
        out.insert(name.trim().to_string(), (st, reason.trim().to_string()));
    }
    Ok(out)
}

fn write_expectations(path: &Path, exp: &BTreeMap<String, (Status, String)>) -> Result<()> {
    let mut s = String::from(HEADER);
    let width = exp.keys().map(String::len).max().unwrap_or(0);
    for (name, (st, reason)) in exp {
        let line = if reason.is_empty() {
            format!("{:<5} {name}", st.as_str())
        } else {
            format!("{:<5} {name:<width$} # {reason}", st.as_str())
        };
        s.push_str(line.trim_end());
        s.push('\n');
    }
    fs::write(path, s)?;
    Ok(())
}

fn compare(results: &BTreeMap<String, Outcome>, target_coredns: bool, update: bool) -> Result<()> {
    let target = if target_coredns { "CoreDNS" } else { "KernDNS" };
    let exp_path = root().join("go/compat/expectations-conformance.txt");
    let expectations = read_expectations(&exp_path)?;
    println!("\nKubernetes [sig-network] DNS e2e tests against {target}:");
    for (name, o) in results {
        let tag = match o.state.as_str() {
            "passed" => "PASS",
            "skipped" => "SKIP",
            _ => "FAIL",
        };
        println!("  {tag:<4} {:>5.0}s {name}", o.seconds);
        if tag != "PASS" && !o.message.is_empty() {
            println!("             {}", o.message);
        }
    }
    let passed = results.values().filter(|o| o.state == "passed").count();
    let total: f64 = results.values().map(|o| o.seconds).sum();
    println!(
        "{target}: {passed}/{} passed ({total:.0} s of spec time)",
        results.len()
    );
    if target_coredns {
        return Ok(());
    }

    let mut new_exp = BTreeMap::new();
    let mut regressions = Vec::new();
    let mut fixed = Vec::new();
    let mut unclassified = Vec::new();
    for (name, o) in results {
        let ok = o.state == "passed";
        let reason = if ok {
            String::new()
        } else {
            format!("{}: {}", o.state, o.message)
        };
        let actual = if ok { Status::Pass } else { Status::Xfail };
        match expectations.get(name) {
            Some((Status::Skip, r)) => {
                new_exp.insert(name.clone(), (Status::Skip, r.clone()));
                continue;
            }
            None => unclassified.push(format!("{:<5} {name} # {reason}", actual.as_str())),
            Some((Status::Pass, _)) if !ok => regressions.push(format!("{name}: {reason}")),
            Some((Status::Xfail, _)) if ok => fixed.push(name.clone()),
            _ => {}
        }
        // hand-written reasons are kept while the result stays the same
        let entry = match expectations.get(name) {
            Some((st, r)) if *st == actual && !r.is_empty() => (actual, r.clone()),
            _ => (actual, reason),
        };
        new_exp.insert(name.clone(), entry);
    }
    // an expected spec that didn't run: renamed or removed in a new release
    let missing: Vec<String> = expectations
        .iter()
        .filter(|(n, (st, _))| *st != Status::Skip && !results.contains_key(*n))
        .map(|(n, _)| n.clone())
        .collect();
    if update {
        write_expectations(&exp_path, &new_exp)?;
        println!("wrote {}", exp_path.display());
        return Ok(());
    }
    let mut failed = false;
    for (title, list) in [
        ("REGRESSIONS (expected pass)", regressions),
        ("NOW PASSING (promote to pass, or run with --update)", fixed),
        (
            "NOT IN go/compat/expectations-conformance.txt (run with --update to add them)",
            unclassified,
        ),
        ("EXPECTED BUT NOT RUN (renamed or removed upstream?)", missing),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn focus_and_skip_regexes() {
        assert_eq!(
            alternation(["[sig-network] DNS ", "a.b"].into_iter()),
            r"\[sig-network\] DNS |a\.b"
        );
        assert!(selected(
            "[sig-network] DNS should provide DNS for services [Conformance]"
        ));
        assert!(!selected(
            "[sig-network] DNS should provide DNS for the cluster [Provider:gce]"
        ));
        assert!(!selected("[sig-network] DNSSEC"));
    }
}
