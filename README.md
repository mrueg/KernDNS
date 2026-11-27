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
| Server: multi-socket UDP (`SO_REUSEPORT`), TCP, DoT (`tls://`), DoH (`https://`, HTTP/1.1 and HTTP/2), DoH3 (`https3://`, HTTP/3), DoQ (`quic://`, RFC 9250) and gRPC (`grpc://`, CoreDNS's `DnsService`), with the `https`, `https3`, `quic` and `grpc_server` connection and stream limits, CoreDNS routing and error semantics, TSIG signing of every response including multi-message transfers, hot reload without dropping listeners | done |
| Plugins | `acl`, `any`, `auto`, `autopath`, `bind`, `bufsize`, `cache`, `cancel`, `chaos`, `debug`, `dns64`, `dnssec`, `dnstap`, `dynupdate`, `erratic`, `errors`, `file`, `forward` (UDP/TCP/DoT), `geoip`, `grpc`, `grpc_server`, `header`, `health`, `hosts`, `https`, `https3`, `k8s_external`, `kubernetes`, `loadbalance`, `local`, `log`, `loop`, `metadata`, `minimal`, `multisocket`, `nsid`, `on`, `pprof`, `prometheus`, `proxyproto`, `quic`, `ready`, `reload`, `rewrite`, `root`, `secondary`, `shed`, `sign`, `siit`, `template`, `timeouts`, `tls`, `trace`, `transfer`, `tsig`, `view`, `whoami` |
| Metrics with CoreDNS's names, labels and buckets (text and protobuf exposition) | done |
| CoreDNS integration tests against KernDNS | 93 pass, 0 expected failures, 25 skipped (Go-only or in-process restarts), see [expectations](go/compat/expectations.txt); harness check: real CoreDNS passes 117 of 118 (`TestQUICReloadDoesNotPanic` is flaky on CoreDNS itself) |
| Differential test against CoreDNS (`file` zones from CoreDNS's tests, 15k+ queries) | no differences |
| Benchmarks against CoreDNS (`cargo xtask bench`) | a level 2 scenario for every plugin, see below |
| `kubernetes` + `k8s_external` | all 74 of CoreDNS's own kubernetes handler test cases replay with identical responses; 57k queries against a live kind cluster match CoreDNS exactly (4 Corefile variants) |
| Go plugin bridge: CoreDNS plugins without a Rust port run in Go inside the chain (e.g. `etcd`) | done (M3) |

### Benchmarks

Every plugin has a level 2 scenario: a directory in
[`bench/plugins/`](bench/plugins/) with a Corefile template, fixtures and
queries, often with several cases (cache hits and misses, forward over
UDP/TCP/DoT, zone sizes, regex rewrites, AXFR, TSIG, ...). `cargo xtask
bench` runs each case against CoreDNS 1.15.0 and KernDNS with the same
Corefile and fixtures, servers pinned to 2 cores (4 threads) of a 4-core
laptop (i7-1065G7) and dnsperf on others, and reports the CPU time per query
each case adds over a `whoami`-only server, next to max QPS and peak RSS.
Plugins without per-query work are listed in
[`bench/plugins/EXEMPT`](bench/plugins/EXEMPT); `cargo xtask bench --check`
(in CI) fails for any other plugin without a scenario.

**These numbers are indicative only.** They come from one `cargo xtask bench
--level 2 --duration 3 --runs 3` (median of 3 runs per case) on a laptop
where other builds were running at the same time, so differences of a few
µs, and all negative values, are noise. `whoami` itself costs 29.0 µs
(CoreDNS) and 23.9 µs (KernDNS) of CPU per query at max load.

| case | CoreDNS +µs/q | KernDNS +µs/q | max QPS CoreDNS → KernDNS | peak RSS CoreDNS → KernDNS |
|---|---:|---:|---|---|
| whoami | 29.0 (base) | 23.9 (base) | 90k → 141k | 59 → 9 MiB |
| acl | +15.0 | -6.1 | 76k → 195k | 60 → 9 MiB |
| acl/block | -6.8 | -0.8 | 112k → 145k | 60 → 10 MiB |
| any | -8.9 | -5.7 | 121k → 178k | 58 → 10 MiB |
| bufsize | +4.2 | +3.3 | 82k → 125k | 59 → 10 MiB |
| cache¹ | -9.2 | -5.8 | 121k → 195k | 69 → 16 MiB |
| cache/miss² | +66.7 | +56.9 | 17k → 6k | 67 → 16 MiB |
| cancel | +17.9 | -4.0 | 39k → 161k | 62 → 10 MiB |
| chaos | +32.2 | +1.6 | 42k → 114k | 59 → 10 MiB |
| dynupdate | +24.4 | +14.0 | 66k → 101k | 61 → 11 MiB |
| dynupdate/update | +1361.1 | +494.3 | 1k → 2k | 66 → 33 MiB |
| erratic | +3.2 | -7.4 | 75k → 196k | 60 → 9 MiB |
| errors | +5.1 | +1.8 | 78k → 128k | 61 → 9 MiB |
| file | +12.6 | +8.3 | 96k → 124k | 71 → 31 MiB |
| file/100k² | +53.8 | +17.6 | 14k → 35k | 145 → 63 MiB |
| file/8a | +3.6 | -2.2 | 106k → 183k | 62 → 11 MiB |
| file/small | +10.3 | +6.3 | 87k → 131k | 62 → 10 MiB |
| forward¹ | +31.8 | +23.5 | 27k → 30k | 64 → 14 MiB |
| forward/dot¹ | +40.4 | +60.6 | 41k → 32k | 78 → 20 MiB |
| forward/tcp¹ | +25.0 | +28.1 | 53k → 50k | 64 → 14 MiB |
| header | -6.4 | -6.1 | 116k → 196k | 60 → 9 MiB |
| hosts | -5.6 | -5.3 | 118k → 191k | 69 → 20 MiB |
| hosts/miss | +15.0 | +2.3 | 76k → 134k | 71 → 20 MiB |
| k8s_external | +1.5 | -1.9 | 108k → 181k | 77 → 21 MiB |
| kubernetes | +20.4 | +2.9 | 71k → 149k | 77 → 22 MiB |
| loadbalance | +10.1 | -0.6 | 96k → 171k | 63 → 12 MiB |
| local | -2.3 | -5.2 | 111k → 182k | 62 → 10 MiB |
| log | +8.6 | +0.1 | 69k → 165k | 65 → 10 MiB |
| log/class-denial | +2.5 | +7.3 | 100k → 127k | 62 → 10 MiB |
| loop | -6.6 | -6.3 | 117k → 193k | 59 → 10 MiB |
| metadata | +1.5 | +1.2 | 87k → 138k | 60 → 9 MiB |
| minimal | +14.4 | -0.6 | 92k → 171k | 71 → 32 MiB |
| nsid | +4.8 | +1.2 | 102k → 150k | 62 → 10 MiB |
| prometheus | +15.3 | -5.0 | 66k → 193k | 64 → 10 MiB |
| rewrite | +3.9 | +2.5 | 102k → 140k | 62 → 10 MiB |
| rewrite/chain | +12.5 | -1.9 | 86k → 181k | 62 → 11 MiB |
| rewrite/regex | +7.3 | +7.7 | 98k → 126k | 63 → 12 MiB |
| rewrite/suffix | +10.8 | -2.6 | 85k → 184k | 64 → 9 MiB |
| secondary | +15.2 | +3.8 | 90k → 144k | 72 → 32 MiB |
| template | +15.4 | +5.5 | 88k → 135k | 61 → 12 MiB |
| template/rcode | +23.9 | +1.4 | 74k → 158k | 61 → 12 MiB |
| timeouts | -7.3 | -6.8 | 119k → 197k | 62 → 9 MiB |
| tls | +2.2 | -2.4 | 124k → 138k | 59 → 10 MiB |
| transfer | +13.7 | -0.8 | 93k → 173k | 71 → 32 MiB |
| transfer/axfr² | +411.3 | +175.6 | 5k → 8k | 24 → 9 MiB |
| tsig | +31.5 | +4.2 | 65k → 115k | 62 → 9 MiB |
| view | +28.7 | -5.0 | 68k → 193k | 62 → 10 MiB |

¹ From a second run of only the cache and forward cases (with its own
`whoami` baseline): in the full run, a burst of load from other processes cut
KernDNS's cache throughput in half.

² After the fixes for the three follow-ups below, from a separate run of
only these cases on a heavily loaded machine (`whoami` reached only 67k →
59k QPS), so only the relative CPU and memory numbers mean much.

What stood out in the first full run, and what it was:

- **cache with misses and constant evictions** (35k → 20k QPS): KernDNS's
  cache gave each of its 256 shards `capacity / 256` entries with a
  minimum of 1, where CoreDNS's minimum is 4, so `success 256` held 256
  answers instead of CoreDNS's 1024 and hit far less often. Every insert
  also locked all 512 shards to update the `cache_entries` gauge. Now the
  entry counts match CoreDNS exactly and the count is an atomic. The
  max-QPS of this case is dominated by the forward backend dropping UDP
  packets at overload (some queries then wait out forward's 2 s read
  timeout, in both servers), so it swings a lot between runs; the rare
  SERVFAILs come from those upstream timeouts, not from the cache.
- **AXFR** (+321 vs +195 µs per transfer): splitting the zone into
  messages encoded every record with hickory's encoder to size it, and
  each message was encoded twice. Now records are sized with the fast
  encoder and messages encoded once: 1.13M → 0.43M instructions per
  transfer of the 100-name zone (callgrind, `hotpath` test), less than
  half of CoreDNS's CPU per transfer in the run above.
- **memory of a 100k-name zone** (247 vs 189 MiB): each name kept a map
  of record lists whose first push reserved room for 4 records of 280
  bytes, and the zone file was held as tokens and then as a record list
  while loading. With one exactly sized list per name and records
  inserted as they are parsed: peak 248 → 66 MiB, steady state 213 → 66
  MiB (CoreDNS: 117 MiB after loading, 177 MiB after 3 s of queries).

Forward over DoT went either way between runs. Signed dynamic
updates (`dynupdate`) cost KernDNS about a third of CoreDNS's CPU. Latency at a fixed rate (half of CoreDNS's
max) is in the detailed report (`target/bench/report.md`).

Kubernetes at scale (`cargo xtask k8s-bench`, a fake API server serving N
Services with 3 endpoints each; both servers watch it via kubeconfig):

| Services | Sync time CoreDNS → KernDNS | RSS after sync | Peak RSS | Max QPS |
|---:|---|---|---|---|
| 1,000 | 0.69 s → 0.23 s | 66 → 19 MiB | 78 → 21 MiB | 18k → 30k |
| 10,000 | 5.6 s → 0.64 s | 121 → 77 MiB | 148 → 77 MiB | 33k → 108k |
| 50,000 | 7.8 s → 1.9 s | 352 → 178 MiB | 495 → 254 MiB | 66k → 125k |

Single laptop runs: treat them as indicative; the plan calls for a
dedicated benchmark machine.

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

### Go plugins

Plugins without a Rust port can run as CoreDNS's own Go code, compiled
into one shared library and loaded at startup:

```sh
cargo xtask build-bridge --plugins etcd,route53   # target/bridge/libkerndns_bridge.so
./target/release/kerndns -bridge target/bridge/libkerndns_bridge.so -conf Corefile
```

They take part in the chain like any other plugin: Rust plugins before
them see their answers, and their `fallthrough` reaches the Rust plugins
after them. `-bridge.prefer cache` runs a plugin in Go even though a Rust
port exists (for comparisons), and `-bridge.sync whoami` runs a CPU-only
Go plugin on the calling thread, which is about 3x cheaper per request.
Plugins that cooperate through Go types (`transfer` and its zone sources,
`kubernetes` and `k8s_external`, `alternate` and `forward`, `autopath`
and the plugin it gets the search path from) must all run on
the same side; KernDNS checks that when it loads the Corefile.

## Layout

```
crates/
  corefile/   Corefile lexer, parser and token dispenser (no DNS dependencies)
  go-bridge/  loads the Go bridge and runs Go plugins in the chain
  core/       plugin model: Handler, Request, ResponseWriter, Controller, Registry, plugin order
  server/     Corefile -> plugin chains -> listeners (UDP, TCP, DoT, DoH, DoH3, DoQ, gRPC), request dispatch
  plugins/    Rust ports of CoreDNS plugins (and the shared service-backend lookup)
  kubernetes/ kubernetes and k8s_external
  kerndns/    the binary
go/compat/    overlay that runs CoreDNS's integration tests against kerndns
go/bridge/    the Go bridge library: CoreDNS plugins behind a C interface
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
cargo xtask bench                       # CoreDNS vs kerndns with dnsperf, every scenario
cargo xtask bench --plugin cache,forward  # level 2 cases of some plugins (+ whoami baseline)
cargo xtask bench --level 3             # common setups only
cargo xtask bench --check               # every plugin has a scenario (no dnsperf needed)
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
