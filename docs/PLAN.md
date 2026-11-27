# KernDNS plan

KernDNS keeps CoreDNS's interface (Corefiles, plugins, flags, log and
metrics formats) and replaces the engine with Rust and Hickory DNS. It has
three goals:

1. Run a Rust port of CoreDNS and selected plugins.
2. Load CoreDNS Go plugins when no Rust port exists.
3. Prove compatibility and performance: CoreDNS's own integration tests run
   against KernDNS, and benchmarks compare the two for the core parts, every
   plugin and common setups such as Kubernetes cluster DNS.

Pinned reference: **CoreDNS v1.15.0** (`third_party/coredns`). Tests,
benchmarks and the Go bridge all use this checkout. Bumping it is one PR that
shows which tests and benchmarks changed.

## Design decisions

- **Hickory DNS for the wire, not for routing.** hickory-server's
  `Catalog`/`Authority` model doesn't match CoreDNS's plugin chain. KernDNS
  uses hickory-server for listeners (UDP, TCP; later DoT, DoH, DoQ),
  hickory-proto for messages, and hickory-resolver/recursor inside plugins
  such as `forward`. Request routing and the chain are KernDNS's own.
- **Mirror CoreDNS's plugin model**, so ports are mechanical and behaviour
  matches: `Handler` returns `(rcode, error)`, `ClientWrite` decides who writes
  error responses, execution order comes from `plugin.cfg` rather than the
  Corefile, and setup code uses a caddy-compatible token dispenser.
- **Go plugins through one bridge library per deployment.** Go's `plugin`
  package can't be used from a Rust process, and only one Go runtime per
  process is reliable. The Go plugins a deployment needs are compiled into one
  `c-shared` library generated from a plugin list, like CoreDNS's own
  `plugin.cfg` build.

## Architecture

```
crates/corefile   Caddyfile-dialect lexer/parser, Dispenser            (done, M0)
crates/core       Handler, Request, ResponseWriter, Controller, Registry, order   (done, M0)
crates/server     Corefile -> chains -> listeners (dns, tls, https), dispatch  (done)
crates/plugins    Rust plugin ports, each behind a cargo feature        (M0: 6 plugins)
crates/kubernetes kubernetes + k8s_external                            (M2)
crates/go-bridge  Rust side of the Go bridge (libloading)              (M3)
go/bridge         c-shared Go library embedding CoreDNS plugins        (M3)
go/compat         overlay running CoreDNS's tests against kerndns     (done, M0)
bench/            benchmark scenarios, runner, report                  (M1+)
```

### Server semantics ported from `dnsserver.Server.ServeDNS`

- No question → SERVFAIL. Class other than IN (unless `chaos` is loaded) → REFUSED.
- EDNS version > 0 → BADVERS.
- Longest zone match over the query name's labels. DS queries go to the
  parent zone. Then `.`, then REFUSED. A zone without plugins → REFUSED.
- After the chain: if the rcode isn't a "client write" code and nothing was
  written, the server writes the error response.
- Every response is scrubbed: EDNS is echoed (`SizeAndDo`) and the message is
  truncated to the client's buffer with TC set (`Truncate`).
- Panics in a chain are recovered (SERVFAIL) unless `debug` is on.

## Go bridge (M3)

**Build:** `cargo xtask build-bridge --plugins kubernetes,etcd,github.com/foo/bar`
generates `go/bridge/plugins_gen.go` with the imports and runs
`go build -buildmode=c-shared -o libkerndns_bridge.so`. The binary loads it
with `libloading` behind a `go-bridge` feature, so KernDNS still runs with no
Go installed.

**C interface** (byte buffers are copied; Go never keeps Rust pointers):

```c
int   kb_version(void);
char* kb_list_plugins(void);                                   // JSON
long  kb_setup(const char* plugin, const char* block_json, char** err);
int   kb_startup(long h);  int kb_shutdown(long h);  int kb_ready(long h);
char* kb_gather_metrics(void);                                 // Prometheus text
void  kb_serve(long h, uint64_t token, const uint8_t* msg, size_t len, const char* meta_json);
// Go -> Rust callbacks
void  rust_write(uint64_t token, const uint8_t* msg, size_t len);
void  rust_call_next(uint64_t token, uint64_t next_token, const uint8_t* msg, size_t len);
void  rust_done(uint64_t token, int rcode, const char* err);
// Rust -> Go
void  kb_next_done(uint64_t next_token, int rcode, const uint8_t* written, size_t len);
```

**Go side:** for each directive, build a throwaway `caddy.Controller` from the
tokens, run the plugin's registered setup, take the `plugin.Plugin` it added
to `dnsserver.Config`, run its `OnStartup` hooks and wrap it around a
`rustNext` handler. `rustNext.ServeDNS` packs the message, calls
`rust_call_next` and parks its goroutine on a channel until `kb_next_done`
arrives, so an OS thread is never blocked inside a callback. A `bridgeWriter`
implements `dns.ResponseWriter` through `rust_write`.

**Rust side:** `GoPlugin` implements `Handler`: it calls `kb_serve`, answers
`rust_call_next` by running the rest of the chain on tokio, and resolves when
`rust_done` fires.

**Limits:**
- Plugins that talk to each other through Go types form affinity groups
  that must all run on one side: `k8s_external` + `kubernetes`, `transfer` +
  its transferers, `alternate` + `forward`, `autopath` + the plugin it
  names (`kubernetes`, `erratic`). These are marked in the order file and
  enforced when the config loads.
- Metadata crosses the boundary as a string map.
- A Go panic is recovered in every exported function and turned into
  SERVFAIL. An optional later out-of-process mode (gRPC over a unix socket)
  gives full crash isolation.

### M3 status

Done: `go/bridge` (the c-shared library, plugins from `plugins_gen.go`),
`crates/go-bridge` (loading it, `GoPlugin`, the callbacks),
`cargo xtask build-bridge --plugins ...`, `kerndns -bridge LIB`
(or `$KERNDNS_BRIDGE`) with `-bridge.prefer` and `-bridge.sync`, Go
metrics appended to `/metrics` (text and protobuf), readiness for `ready`,
and the affinity check when a Corefile loads.

- `cargo xtask compat-test --bridge` runs CoreDNS's own etcd tests (build
  tag `etcd`) against KernDNS with the Go `etcd` plugin, against a
  throwaway local etcd: `TestEtcdCache` and `TestEtcdCredentials` pass;
  `TestEtcdStubAndProxyLookup` needs a live internet address and fails on
  CoreDNS too. A differential run of `log`, `cache` (Rust) + `etcd` (Go) +
  `whoami` (Rust, via `fallthrough`) against CoreDNS shows no differences.
- Per-request cost (`cargo test --release -p kerndns-server --test hotpath
  -- --ignored bridge`), in-process, one query:

  | Chain | Rust | Go, bridged (async) | Go, bridged (`-bridge.sync`) |
  |---|---:|---:|---:|
  | `whoami` | 1.2 µs | 17.8 µs | 5.4 µs |
  | `metadata` → `whoami` (Go plugin calling next) | 1.4 µs | 32.4 µs | 8.2 µs |

  The default runs each request on a goroutine and wakes the Rust task
  from Go's callbacks (two cross-thread hand-offs). `-bridge.sync` runs
  the Go handler on the calling thread and the Rust rest of the chain
  inline (`block_in_place`); it blocks a runtime worker while the Go
  plugin waits on the network, so it is meant for CPU-only plugins.
- Not yet: third-party plugins outside plugin.cfg's order, Go metadata
  flowing back to Rust, and the out-of-process mode (M5).

**Choosing per directive:** Rust port if one exists, else the bridge if it
provides the plugin, else an error saying how to build the bridge with it.
`prefer go|rust` and `cache@go` override this for A/B tests and benchmarks.

## Plugin waves

| Wave | Plugins |
|---|---|
| M0 | `whoami`, `log`, `errors`, `debug`, `bind`, `root` (done) |
| 1: minimal server | `file`, `health`, `ready`, `prometheus`, `forward`, `cache`, `hosts`, `reload`, `loop`, `chaos` (done) |
| 2: Kubernetes | `kubernetes`, `k8s_external` (done) |
| 3: authoritative | `file`, `auto`, `secondary`, `transfer`, `any`, `minimal`, `loadbalance`, `local`, `tsig` (done) |
| 4: policy and rewriting | `rewrite`, `template`, `acl`, `metadata`, `view`, `cancel`, `timeouts`, `header`, `dns64`, `autopath`, `nsid`, `tls` |
| 5: DNSSEC and the rest | `dnssec`, `sign`, `alternate`, and the remaining in-tree plugins as needed |

Through the Go bridge until someone needs a port: `etcd`, `route53`,
`clouddns`, `azure`, third-party plugins.

`tls`, `tsig`, `header` and `transfer` are ported (with DoT and DoH
listeners), and so are `secondary` (with RFC 9432 catalog zones) and `dynupdate`
(its database is KernDNS's own file format, replaced atomically per commit,
instead of bbolt). `auto` loads zones from a directory and rescans it with
the `file` zone code, and `multisocket` sets the number of `SO_REUSEPORT`
servers (UDP socket and TCP listener each) per address. The upstream tests
still failing are mostly blocked by the `https`/`https3`/`quic`/`grpc_server`
listener plugins and transports (13), `autopath` (4), `dns64`, `dnssec`,
`siit` and `shed` (4) and ACME (1); `view`'s two tests bind a port another
running instance holds, which CoreDNS allows because all its listeners use
`SO_REUSEPORT` and KernDNS refuses on purpose (2).

Performance follow-ups from the first benchmarks, done:

- CPU per query for cheap chains: responses are encoded once (truncation
  happens while encoding, not before) by KernDNS's own encoder
  (`kerndns_core::wire`, falling back to hickory for uncommon record types),
  and `Request::name` no longer allocates a lowercased copy of the name.
  `whoami`: 24.3k → 10.4k instructions per query (callgrind on
  `cargo test --release -p kerndns-server --test hotpath -- --ignored`).
- `forward` reads UDP answers into a buffer of the client's EDNS size (at
  least 512 bytes, like CoreDNS) instead of 64 KiB per query.
- Kubernetes: index entries share one allocation of each object key, and
  free heap is returned to the OS after every (re-)list. RSS after syncing
  50k Services: 238 → 171 MiB.
- TCP, DoT and DoH are KernDNS's own listeners; hickory-server is gone.

- `prometheus` reports from a hook the server runs after its one final
  encode, instead of encoding the response again to measure it
  (`prometheus` + `whoami`: 20.7k → 14.9k instructions per query). The
  size recorded is the bytes sent: unlike CoreDNS, it includes the echoed
  OPT record and reflects truncation.

Open: prometheus label lookups cost ~1.7k instructions per query.

## Kubernetes plugin port (M2)

- `kube` / `kube-runtime` watchers and reflectors with `k8s-openapi`.
- Like `plugin/kubernetes/object`: convert each watch event into a small
  struct with only the fields DNS needs. Never keep full API objects. This is
  the main memory lever and is benchmarked against Go's informer cache.
- Watched: Services and EndpointSlices always. Namespaces only with
  `namespace_labels`. Pods only with `pods verified`. ServiceImports and
  multicluster EndpointSlices only with `multicluster`.
- Every option in the CoreDNS README, including `endpoint`, `tls`,
  `kubeconfig`, `namespaces`, `labels`, `namespace_labels`,
  `pods insecure|verified|disabled`, `endpoint_pod_names`, `ttl`,
  `noendpoints`, `fallthrough`, `ignore empty_service`,
  `apiserver_qps/burst`, `startup_timeout` and `multicluster`.
- Records: A, AAAA, SRV, PTR, ExternalName CNAME, headless, wildcards,
  `dns-version`, and correct NXDOMAIN vs NODATA.
- `ready` reports not-ready until all watchers have synced. Implements
  `Transferer` for AXFR. Exposes the same `coredns_kubernetes_*` metrics.
- Tests: ported table tests from `plugin/kubernetes/*_test.go`, the
  `coredns/ci` kind tests, and difftests against the Go plugin on the same
  cluster.

### M2 status

- All 74 cases of CoreDNS's kubernetes handler suites (serve, namespaces,
  not-synced, pod modes, empty services, apex, case preservation) are
  extracted from the Go tests (`cargo xtask k8s-cases`) and replay with
  identical responses (`crates/kubernetes/tests/upstream_cases.rs`).
- `cargo xtask k8s-difftest` against a live kind cluster: 57,344 queries over
  four Corefile variants (kubeadm-like, `pods verified` +
  `endpoint_pod_names`, `namespaces` + `ignore empty_service`,
  `k8s_external` with `headless`): no differences.
- `cargo xtask k8s-bench`: faster sync and less memory than CoreDNS at 1k,
  10k and 50k services (see README).
- `autopath @kubernetes` works with `pods verified`: the search path comes
  from the client pod's namespace, like CoreDNS's `AutoPath`.
- Not ported yet: `multicluster`, `zonal`, `apiserver_*` limits, AXFR
  (needs `transfer`), `coredns_kubernetes_*` DNS
  programming latency metrics. The `coredns/ci` kind tests haven't been
  run yet. Resident memory after a large sync is higher than the live
  index needs because the allocator keeps freed list pages; a different
  allocator or smaller pages would trade that against sync time.

## Testing

1. **CoreDNS integration tests, unmodified** (`cargo xtask compat-test`, done).
   A Go overlay replaces `test/server.go` so the helpers start `kerndns`.
   Each test runs in its own process, and results are compared with
   `go/compat/expectations.txt` (pass / xfail / skip, each with a reason).
   A test counts as passing only if it really started `kerndns`. CI fails on
   regressions, unclassified tests and xfails that start passing.
2. **`coredns/ci` end-to-end tests** (kind-based, including Kubernetes):
   a nightly job with the KernDNS image.
3. **Plugin unit tests:** the table tests from each plugin's `*_test.go` are
   ported to Rust, and each plugin lists which upstream files it covers.
4. **Differential testing** (`cargo xtask difftest`): same Corefile and
   fixtures against CoreDNS and KernDNS, a query corpus including fuzzed
   queries, diffs normalised for TTL and RRset order. A plugin becomes the
   default Rust implementation only after it passes.
5. **Fuzzing:** the Corefile parser and the bridge's message handling.

## Benchmarks: CoreDNS vs KernDNS

Same pinned CoreDNS version, Corefile, fixtures and machine (pinned cores,
with the load generator on separate cores). Where it's useful, a third
column shows KernDNS running the Go plugin through the bridge (`@go`), which
isolates the bridge's cost.

**Measured:** max QPS at a fixed loss threshold, p50/p99/p99.9 latency at
10%, 50% and 80% of CoreDNS's max, CPU time per query, RSS over the run and
startup time. For Kubernetes, also sync time and how long a change takes to
show up in DNS. Tools: `dnsperf`, `resperf`, flamegraphs saved with results.
Each scenario runs N times and reports the median and spread.

- **Level 1, micro** (criterion vs `go test -bench`): message parse/pack,
  Corefile parse, chain dispatch, each plugin's hot path, and the bridge
  round trip.
- **Level 2, per plugin:** `bench/plugins/<name>/` with Corefile, fixtures and
  queries. The result is the added cost over a `whoami` baseline, with cases
  specific to each plugin (cache hit ratios and sizes, forward
  protocols and failures, zone sizes, regex rewrites, DNSSEC cold/warm). A
  plugin isn't finished without a scenario; `xtask bench --check` enforces this.
- **Level 3, common setups:** kubeadm cluster DNS, caching forwarder,
  authoritative server, split horizon, DoT/DoH frontend, and a mixed bridge
  chain vs all-Go CoreDNS.
- **Kubernetes at scale:** kind + kwok with 1k/10k/50k Services and up to
  500k endpoints, a realistic in-cluster query mix including the `ndots:5`
  search-path NXDOMAINs, memory as the cluster grows, time to sync and become
  ready, change propagation, API server load, and behaviour when the API
  server restarts.

**CI:** level 1 and a level 2 subset on every PR, failing on regressions
above a threshold, with history tracked. Everything else nightly on a
dedicated machine, with a published report.

## Milestones

| | Scope | Exit criteria |
|---|---|---|
| **M0** (done) | Workspace, Corefile parser, core traits, hickory server, first plugins | `dig` works; compat overlay runs every upstream test against `kerndns` with every result classified |
| **M1** (done) | Wave 1 plugins, `reload`, `/metrics` | All relevant `test/` tests pass or are classified with a plugin reason; difftest in CI; bench harness with level 1/2 for wave 1 |
| **M2** (done) | `kubernetes` + `k8s_external` | Ported unit tables, `coredns/ci` kind tests and Go difftest all pass; scale benchmarks published, with memory at or below CoreDNS |
| **M3** (done) | Go bridge MVP | Go `etcd` inside a Rust chain; bridge micro-benchmarks; affinity groups enforced |
| **M4** | Waves 3–4, DoT/DoH/DoQ/gRPC | Compat pass rate goes up; every plugin has a level 2 scenario |
| **M5** | Wave 5, optional out-of-process bridge, packaging | Nightly level 3 report; drop-in image replacing CoreDNS in kubeadm |

## Risks

- **Compat overlay blind spots:** some upstream tests check Go internals or
  start an in-process CoreDNS (for example through `caddy.Restart`). Every
  skip is listed with a reason, so the pass rate can't be inflated quietly.
- **Kubernetes semantics:** many edge cases. Difftest against the Go plugin
  on the same cluster is the safety net.
- **Benchmark noise:** without a dedicated machine with pinned cores, Go vs
  Rust differences under 5–10% won't mean anything.
- **The fake caddy setup in the Go bridge** and **per-query bridge cost**.
  The bridge column in the benchmarks measures the second one directly.
