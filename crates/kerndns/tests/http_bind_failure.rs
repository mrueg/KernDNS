//! `prometheus` and `ready` addresses that cannot be bound do not stop
//! KernDNS, as in CoreDNS: their `OnStartup` errors go through
//! `uniq.ForEach`, which drops them. `prometheus` logs
//! `[ERROR] Failed to start metrics handler: ...`, `ready` logs nothing,
//! DNS is served, and a reload does not retry the bind (the address stays
//! "done" in `uniq`). Runs the binary, as that is what CoreDNS users see.

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// One `whoami.example.org. A` query; the response's rcode.
fn query(port: u16) -> Option<u8> {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["whoami", "example", "org"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    s.send_to(&q, ("127.0.0.1", port)).ok()?;
    let mut buf = [0u8; 512];
    let n = s.recv(&mut buf).ok()?;
    (n >= 12 && buf[..2] == [0x12, 0x34]).then_some(buf[3] & 0x0f)
}

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn unbindable_metrics_and_ready_addresses_are_not_fatal() {
    run(env!("CARGO_BIN_EXE_kerndns"));
}

/// The same against CoreDNS (`target/coredns-ref`, from
/// `cargo xtask difftest`, or `$COREDNS_REF`).
#[test]
#[ignore = "needs a CoreDNS binary"]
fn against_coredns() {
    let bin = std::env::var("COREDNS_REF")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/coredns-ref").to_string());
    run(&bin);
}

fn run(bin: &str) {
    // plain listeners (no SO_REUSEPORT), so the reuseport binds fail
    let metrics = TcpListener::bind("127.0.0.1:0").unwrap();
    let ready = TcpListener::bind("127.0.0.1:0").unwrap();
    let (mport, rport) = (metrics.local_addr().unwrap().port(), ready.local_addr().unwrap().port());
    let dns = free_udp_port();

    // two blocks with the same addresses share one listener: one log line
    let block = |zone: &str| {
        format!(
            "{zone}:{dns} {{\n bind 127.0.0.1\n prometheus 127.0.0.1:{mport}\n ready 127.0.0.1:{rport}\n whoami\n}}\n"
        )
    };
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("http-bind-failure-{dns}"));
    std::fs::create_dir_all(&dir).unwrap();
    let corefile = dir.join("Corefile");
    std::fs::write(&corefile, block(".") + &block("example.org")).unwrap();

    let mut child = Command::new(bin)
        .arg("-conf")
        .arg(&corefile)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = Arc::new(Mutex::new(String::new()));
    for pipe in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let out = out.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                let mut o = out.lock().unwrap();
                o.push_str(&line);
                o.push('\n');
            }
        });
    }
    let mut child = Kill(child);
    let log = || out.lock().unwrap().clone();

    wait_for("DNS", || {
        if let Ok(Some(status)) = child.0.try_wait() {
            panic!("kerndns exited ({status}):\n{}", log());
        }
        query(dns) == Some(0)
    });
    let want =
        format!("[ERROR] Failed to start metrics handler: listen tcp 127.0.0.1:{mport}: bind: address already in use");
    let got = log();
    assert_eq!(got.matches(&want).count(), 1, "log:\n{got}");
    assert!(
        !got.contains("plugin/ready") && !got.contains(&format!("127.0.0.1:{rport}")),
        "CoreDNS logs nothing for ready:\n{got}"
    );

    // with the addresses free, a reload still does not bind them
    drop((metrics, ready));
    let ok = Command::new("kill")
        .args(["-USR1", &child.0.id().to_string()])
        .status()
        .unwrap();
    assert!(ok.success());
    wait_for("reload", || log().contains("Reloading complete"));
    assert_eq!(query(dns), Some(0));
    for port in [mport, rport] {
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_err(),
            "port {port} bound after reload:\n{}",
            log()
        );
    }
    let got = log();
    assert_eq!(got.matches(&want).count(), 1, "no new bind attempt on reload:\n{got}");
    assert!(child.0.try_wait().unwrap().is_none());
}
