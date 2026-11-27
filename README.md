# KernDNS

A DNS server that speaks [CoreDNS](https://coredns.io)'s language (Corefiles,
plugins, flags and log formats) with a Rust core built on
[Hickory DNS](https://github.com/hickory-dns/hickory-dns).

KernDNS aims to:

1. **Run a Rust port of CoreDNS and selected plugins.** The same Corefile
   gives the same answers.
2. **Load CoreDNS Go plugins** when no Rust port exists yet, through a Go
   bridge library (planned, see [docs/PLAN.md](docs/PLAN.md)).
3. **Prove it**: CoreDNS's own integration tests run against KernDNS, and
   benchmarks compare the two plugin by plugin.

> KernDNS is an independent project. It is not affiliated with or endorsed by
> the CoreDNS project or the CNCF.

## The name

```
Hickory DNS -> Wood -> Heartwood -> Kernholz -> Kern -> CoreDNS
```

KernDNS is built on **Hickory DNS**. Hickory is a hardwood, and the core of a
tree trunk is its **heartwood**, in German ***Kernholz***. *Kernholz* is
*Kern* (core) + *Holz* (wood), and ***Kern*** is German for "core", which
brings us back to **CoreDNS**, whose interface KernDNS implements. So the
name says what the project is: a hickory core inside a CoreDNS-shaped trunk.

## Status

Milestones **M0**, **M1** and **M2** are done.

| Part | State |
|---|---|
| Corefile parser: server blocks, snippets, `import`, env vars, caddy-compatible dispenser | done |
| Plugin model mirroring CoreDNS (`Handler`, `ResponseWriter`, `plugin.cfg` order, `ClientWrite` rules) | done |
| Server: multi-socket UDP (`SO_REUSEPORT`), TCP, DoT (`tls://`), DoH (`https://`, HTTP/1.1 and HTTP/2), CoreDNS routing and error semantics, TSIG signing of every response including multi-message transfers, hot reload without dropping listeners | done |
| Plugins | `any`, `bind`, `bufsize`, `cache`, `chaos`, `debug`, `dynupdate`, `errors`, `file`, `forward` (UDP/TCP/DoT), `header`, `health`, `hosts`, `k8s_external`, `kubernetes`, `loadbalance`, `log`, `loop`, `minimal`, `nsid`, `prometheus`, `ready`, `reload`, `rewrite`, `root`, `secondary`, `tls`, `transfer`, `tsig`, `whoami` |
| Metrics with CoreDNS's names, labels and buckets (text and protobuf exposition) | done |
| CoreDNS integration tests against KernDNS | 57 pass, 39 expected failures (plugins not ported yet), 22 skipped (Go-only or in-process restarts), see [expectations](go/compat/expectations.txt); harness check: real CoreDNS passes 117 of 118 |
| Differential test against CoreDNS (`file` zones from CoreDNS's tests, 15k+ queries) | no differences |
| Benchmarks against CoreDNS (`cargo xtask bench`) | see below |
| `kubernetes` + `k8s_external` | all 74 of CoreDNS's own kubernetes handler test cases replay with identical responses; 57k queries against a live kind cluster match CoreDNS exactly (4 Corefile variants) |
| DoQ / HTTP/3 / gRPC listeners, Go plugin bridge | planned (M3/M4) |

### Benchmarks

`cargo xtask bench` on a 4-core laptop (i7-1065G7), servers pinned to 2 cores
(4 threads), dnsperf on others; same Corefile and fixtures for both:

| Scenario | CoreDNS 1.15.0 QPS | KernDNS QPS | Peak RSS CoreDNS → KernDNS |
|---|---:|---:|---|
| whoami | 116k | 153k | 62 → 7 MiB |
| log + whoami | 45k | 145k | 67 → 8 MiB |
| prometheus + whoami | 55k | 174k | 65 → 8 MiB |
| hosts (10k entries) | 77k | 183k | 73 → 17 MiB |
| file (10k-name zone) | 66k | 153k | 75 → 29 MiB |
| forward | 24k | 38k | 66 → 52 MiB |
| cache + forward | 75k | 133k | 71 → 44 MiB |
| resolver (errors, health, ready, prometheus, cache, forward, loop, reload) | 84k | 107k | 73 → 46 MiB |

Latency at a fixed rate (half of CoreDNS's max) is equal or lower in every
scenario, with much smaller worst cases.

Kubernetes at scale (`cargo xtask k8s-bench`, a fake API server serving N
Services with 3 endpoints each; both servers watch it via kubeconfig):

| Services | Sync time CoreDNS → KernDNS | RSS after sync | Peak RSS | Max QPS |
|---:|---|---|---|---|
| 1,000 | 0.69 s → 0.23 s | 66 → 19 MiB | 78 → 21 MiB | 18k → 30k |
| 10,000 | 5.6 s → 0.64 s | 121 → 77 MiB | 148 → 77 MiB | 33k → 108k |
| 50,000 | 7.8 s → 1.9 s | 352 → 178 MiB | 495 → 254 MiB | 66k → 125k | Single laptop runs: treat them as
indicative; the plan calls for a dedicated benchmark machine.

## Quick start

```sh
cargo build --release
cat > Corefile <<'EOF'
example.org:1053 {
    errors
    log
    whoami
}
EOF
./target/release/kerndns -conf Corefile
dig @127.0.0.1 -p 1053 www.example.org
```

The flags match CoreDNS: `-conf`, `-dns.port`, `-pidfile`, `-plugins`,
`-quiet` and `-version`. With no Corefile, KernDNS serves `.:53` with
`whoami` and `log`, like CoreDNS.

## Layout

```
crates/
  corefile/   Corefile lexer, parser and token dispenser (no DNS dependencies)
  core/       plugin model: Handler, Request, ResponseWriter, Controller, Registry, plugin order
  server/     Corefile -> plugin chains -> hickory-server listeners, request dispatch
  plugins/    Rust ports of CoreDNS plugins (and the shared service-backend lookup)
  kubernetes/ kubernetes and k8s_external
  kerndns/    the binary
go/compat/    overlay that runs CoreDNS's integration tests against kerndns
third_party/coredns   CoreDNS v1.15.0 (git submodule): tests and reference behaviour
xtask/        cargo xtask commands
docs/PLAN.md  architecture, roadmap, testing and benchmark plan
```

### Writing a plugin

Plugins port almost line by line from Go:

| CoreDNS (Go) | KernDNS (Rust) |
|---|---|
| `plugin.Handler` / `ServeDNS(ctx, w, r) (int, error)` | `Handler::serve_dns(&self, ctx, w, req) -> HandlerResult` |
| `request.Request{W: w, Req: r}` | `Request` (`name()`, `qtype()`, `ip()`, `size()`, `reply()`, ...) |
| `setup(c *caddy.Controller)` with `c.Next()`, `c.RemainingArgs()`, `c.NextBlock()` | `PluginFactory::setup(&self, c: &mut Controller)` with `c.next()`, `c.remaining_args()`, `c.next_block()` |
| `dnsserver.GetConfig(c).AddPlugin(...)` | `c.add_plugin(...)` |
| `plugin.NextOrFailure(...)` | `next_or_failure(...)` |

[`crates/plugins/src/whoami.rs`](crates/plugins/src/whoami.rs) is the smallest
complete example.

## Testing

```sh
cargo test --workspace                  # unit tests
git submodule update --init             # CoreDNS checkout (needed once)
cargo xtask compat-test                 # CoreDNS integration tests against kerndns
cargo xtask compat-test --run TestEDNS0 # a subset
cargo xtask compat-test --update        # accept the current results
cargo xtask compat-test --target coredns  # same tests against real CoreDNS (checks the harness)
cargo xtask difftest                    # same zones in CoreDNS and kerndns, diff the answers
cargo xtask bench                       # CoreDNS vs kerndns with dnsperf
cargo xtask k8s-cases                   # regenerate the upstream kubernetes test cases (Go)
cargo xtask k8s-bench                   # kubernetes plugin at 1k/10k/50k services
# live-cluster comparison (workloads in namespaces testns/other):
kubectl --context CTX apply -f bench/k8s/workloads.yaml
cargo xtask k8s-difftest --context CTX
kubectl --context CTX delete ns testns other
```

`compat-test` builds `kerndns` and compiles CoreDNS's `test` package with a
[Go overlay](go/compat/) that replaces the server-start helpers with ones that
run the `kerndns` binary. The upstream test files run unmodified. Each test
runs in its own process, and the results are compared with
[`go/compat/expectations.txt`](go/compat/expectations.txt):

- **pass**: must keep passing.
- **xfail**: fails today, with the reason; the run fails when one starts passing, so it gets promoted.
- **skip**: can't apply to KernDNS (tests Go internals or starts an in-process CoreDNS), with the reason.

A test only counts as passing if it actually started `kerndns`. Tests that
pass without ever starting the server are classified as `skip`.

## License

Apache-2.0, the same as CoreDNS.
