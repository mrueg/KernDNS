//! A reload of the `kerndns` binary whose new Corefile fails to start (a
//! startup hook errors) keeps serving the running configuration, logs like
//! caddy and CoreDNS's `reload` plugin, and counts the failure in
//! `coredns_reload_failed_total` (only the `reload` plugin does, not
//! SIGUSR1).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// RCODE of `whoami.example.org. A` over UDP, `None` on timeout.
fn rcode(port: u16) -> Option<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["whoami", "example", "org"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    s.send_to(&q, ("127.0.0.1", port)).unwrap();
    let mut buf = [0u8; 4096];
    let n = s.recv(&mut buf).ok()?;
    assert!(n >= 12 && buf[..2] == [0x12, 0x34]);
    Some(buf[3] & 0x0f)
}

/// Body of `GET path`, `None` if nothing listens.
fn http_get(port: u16, path: &str) -> Option<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").ok()?;
    let mut out = String::new();
    s.read_to_string(&mut out).ok()?;
    Some(out)
}

/// The value of the sample line starting with `prefix` (name and labels).
fn metric(port: u16, prefix: &str) -> Option<f64> {
    let body = http_get(port, "/metrics")?;
    body.lines()
        .find(|l| l.starts_with(prefix))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct Server {
    child: Child,
    log: PathBuf,
}

impl Server {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.child.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(dir: &Path, corefile: &Path) -> Server {
    let log = dir.join("kerndns.log");
    let out = std::fs::File::create(&log).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_kerndns"))
        .arg("-conf")
        .arg(corefile)
        .stdout(out.try_clone().unwrap())
        .stderr(out)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    Server { child, log }
}

#[test]
fn failed_reload_keeps_running_config() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("reload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let corefile = dir.join("Corefile");
    let (dns, health, prom) = (free_port(), free_port(), free_port());
    let running = format!(
        ".:{dns} {{\n    bind 127.0.0.1\n    reload 2s 0s\n    health 127.0.0.1:{health}\n    prometheus 127.0.0.1:{prom}\n    whoami\n}}\n"
    );
    std::fs::write(&corefile, &running).unwrap();
    let srv = start(&dir, &corefile);
    wait_for("the server", || rcode(dns) == Some(0));
    wait_for("the running hash", || {
        srv.log().contains("Running configuration SHA512")
    });
    assert_eq!(metric(prom, "coredns_reload_failed_total"), Some(0.0));

    // pprof can't bind an address held without SO_REUSEPORT; the zone
    // change would make whoami.example.org REFUSED
    let busy = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_port = busy.local_addr().unwrap().port();
    let failing = format!(
        "example.net:{dns} {{\n    bind 127.0.0.1\n    reload 2s 0s\n    health 127.0.0.1:{health}\n    pprof 127.0.0.1:{busy_port}\n    prometheus 127.0.0.1:{prom}\n    whoami\n}}\n"
    );
    std::fs::write(&corefile, &failing).unwrap();
    wait_for("the failed reload", || {
        srv.log().contains("Corefile changed but reload failed")
    });
    let log = srv.log();
    let err = format!("starting with listener file descriptors: plugin/pprof: listen tcp 127.0.0.1:{busy_port}");
    assert!(log.contains("[INFO] Reloading\n"), "{log}");
    assert!(log.contains(&format!("[ERROR] Restart failed: {err}")), "{log}");
    assert!(
        log.contains(&format!(
            "[ERROR] plugin/reload: Corefile changed but reload failed: {err}"
        )),
        "{log}"
    );
    assert!(!log.contains("Reloading complete"), "{log}");

    // the old configuration still serves, its endpoints are back
    assert_eq!(rcode(dns), Some(0));
    assert!(http_get(health, "/health").is_some_and(|b| b.starts_with("HTTP/1.1 200")));
    assert_eq!(metric(prom, "coredns_reload_failed_total"), Some(1.0));
    let info = http_get(prom, "/metrics").unwrap();
    assert_eq!(
        info.lines()
            .filter(|l| l.starts_with("coredns_reload_version_info"))
            .count(),
        1,
        "{info}"
    );

    // the same file isn't retried
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(metric(prom, "coredns_reload_failed_total"), Some(1.0));

    // SIGUSR1 reloads it anyway; a failure there isn't the reload plugin's
    srv.signal("-USR1");
    wait_for("the SIGUSR1 reload", || srv.log().contains("[ERROR] SIGUSR1: "));
    let log = srv.log();
    assert!(log.contains("[INFO] SIGUSR1: Reloading\n"), "{log}");
    assert!(log.contains(&format!("[ERROR] SIGUSR1: {err}")), "{log}");
    assert_eq!(log.matches("Corefile changed but reload failed").count(), 1, "{log}");
    assert_eq!(rcode(dns), Some(0));
    assert_eq!(metric(prom, "coredns_reload_failed_total"), Some(1.0));

    // a fixed Corefile reloads
    drop(busy);
    std::fs::write(
        &corefile,
        failing.replace(&format!("    pprof 127.0.0.1:{busy_port}\n"), ""),
    )
    .unwrap();
    wait_for("the good reload", || srv.log().contains("Reloading complete"));
    assert_eq!(rcode(dns), Some(5), "REFUSED: the new zones serve");
    assert_eq!(metric(prom, "coredns_reload_failed_total"), Some(1.0));
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}
