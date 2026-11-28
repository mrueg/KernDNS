# KernDNS

A DNS server that speaks [CoreDNS](https://coredns.io)'s language (Corefiles,
plugins, flags and log formats) with a Rust core built on
[Hickory DNS](https://github.com/hickory-dns/hickory-dns).

KernDNS aims to:

1. **Run a Rust port of CoreDNS and selected plugins.** The same Corefile
   gives the same answers.
2. **Load CoreDNS Go plugins** when no Rust port exists yet, through a Go
   bridge library (see [docs/PLAN.md](docs/PLAN.md)).
3. **Prove it**: CoreDNS's own integration tests run against KernDNS, and
   benchmarks compare the two plugin by plugin.

> [!WARNING]
> **KernDNS is a prototype. Do not use it in production.** It is an
> experiment in how far a Rust port of CoreDNS can go. It has not been
> audited or run under real traffic, and its interfaces, flags and image
> can change without notice.

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

Milestones **M0** to **M4** are done; **M5** is mostly done (see
[docs/PLAN.md](docs/PLAN.md) for the plan and each milestone's status).

| Milestone | What it delivered |
|---|---|
| **M0** | Workspace, Corefile parser, core traits, the server on hickory-proto, first plugins; CoreDNS's integration tests run against `kerndns` with every result classified |
| **M1** | The minimal server (`file`, `forward`, `cache`, `hosts`, `health`, `ready`, `prometheus`, `reload`, `loop`, `chaos`, ...), `/metrics` with CoreDNS's names, the differential test and the benchmark harness |
| **M2** | `kubernetes` and `k8s_external`; since then at parity with CoreDNS 1.15.0, including zone transfers, `multicluster` and `zonal` |
| **M3** | The Go bridge: CoreDNS plugins without a Rust port run in Go inside the Rust chain |
| **M4** | Authoritative and policy plugins, DoT, DoH, DoH3, DoQ and gRPC listeners, a level 2 benchmark for every plugin |
| **M5** | DNSSEC and the remaining plugins (every plugin in CoreDNS's `plugin.cfg` except the cloud backends `route53`, `clouddns`, `azure` and `nomad`, which run through the bridge), `etcd` in Rust, ACME certificates, a drop-in container image (`ghcr.io/mrueg/kerndns`), CoreDNS's end-to-end Kubernetes tests in CI, level 3 benchmarks of common setups, fuzzing. Open: a nightly level 3 report on a dedicated machine, and the optional out-of-process bridge |

In detail:

| Part | State |
|---|---|
| Corefile parser: server blocks, snippets, `import`, env vars, caddy-compatible dispenser | done |
| Plugin model mirroring CoreDNS (`Handler`, `ResponseWriter`, `plugin.cfg` order, `ClientWrite` rules) | done |
| Server: multi-socket UDP (`SO_REUSEPORT`), TCP, DoT (`tls://`), DoH (`https://`, HTTP/1.1 and HTTP/2), DoH3 (`https3://`, HTTP/3), DoQ (`quic://`, RFC 9250) and gRPC (`grpc://`, CoreDNS's `DnsService`), with the `https`, `https3`, `quic` and `grpc_server` connection and stream limits, CoreDNS routing and error semantics, TSIG signing of every response including multi-message transfers, hot reload without dropping listeners | done |
| Plugins ([parity with CoreDNS 1.15.0](docs/PLAN.md#parity-with-coredns-1150-the-other-plugins)) | `acl`, `any`, `auto`, `autopath`, `bind`, `bufsize`, `cache`, `cancel`, `chaos`, `debug`, `dns64`, `dnssec`, `dnstap`, `dynupdate`, `erratic`, `errors`, `etcd`, `file`, `forward` (UDP/TCP/DoT/DoH/DoQ), `geoip`, `grpc`, `grpc_server`, `header`, `health`, `hosts`, `https`, `https3`, `k8s_external`, `kubernetes`, `loadbalance`, `local`, `log`, `loop`, `metadata`, `minimal`, `multisocket`, `nsid`, `on`, `pprof`, `prometheus`, `proxyproto`, `quic`, `ready`, `reload`, `rewrite`, `root`, `secondary`, `shed`, `sign`, `siit`, `template`, `timeouts`, `tls`, `trace`, `transfer`, `tsig`, `view`, `whoami` |
| Metrics with CoreDNS's names, labels and buckets (text and protobuf exposition) | done |
| CoreDNS integration tests against KernDNS | 109 pass, 1 expected failure (also fails for CoreDNS), 12 skipped (Go internals, checks of the Go source, a shared in-process metrics registry), see [expectations](go/compat/expectations.txt); harness check: real CoreDNS passes 120 of 122 (`TestDynUpdateKeaLifecycle` skips without Kea; `TestQUICReloadDoesNotPanic` is flaky on CoreDNS itself; `TestEtcdStubAndProxyLookup` expects an outdated address for example.com) |
| Differential test against CoreDNS (`file` zones from CoreDNS's tests, 15k+ queries) | no differences |
| Differential test of `etcd` against CoreDNS (one throwaway etcd: 500 services plus the unit tests' records, leases, weights, out-of-zone targets, broken JSON; 2 Corefiles, 32k queries) | no differences |
| CoreDNS's plugin table tests: 51 plugins' test tables extracted from the Go source (`cargo xtask plugin-cases`) and replayed through KernDNS | 1,257 of 1,962 rows pass, 10 expected failures (features not ported yet), the rest skipped with a reason; see [docs/plugin-cases.md](docs/plugin-cases.md) |
| CoreDNS's end-to-end Kubernetes tests ([coredns/ci](https://github.com/coredns/ci) `test/kubernetes`) with the KernDNS image as a kind cluster's DNS (CI job `kind`, with CoreDNS's own image as a control) | all 13 that exercise the cluster DNS pass; 2 skipped (one depends on the CI runner's resolv.conf and fails for CoreDNS too, one tests an in-process Go CoreDNS), see [expectations](go/compat/expectations-kind.txt) |
| Kubernetes' own `[sig-network] DNS` end-to-end tests (test/e2e/network/dns*.go: all 8 DNS `[Conformance]` specs and the 12 others that run on kind, incl. the `[Serial]` ConfigMap stubDomain/upstream tests) plus the `[sig-network] Services` conformance tests, from the `e2e.test` of Kubernetes v1.37.0, with the KernDNS image swapped into kind's kube-system/coredns Deployment and kubeadm's Corefile unchanged (CI job `k8s-conformance`, with CoreDNS 1.15.0's image as a control) | all 37 pass, the same as CoreDNS; see [expectations](go/compat/expectations-conformance.txt) |
| Fuzzing (`fuzz/`: Corefile setup, the request path, the Go bridge's messages; CI runs each target for a minute) | done; the crashes found are fixed with regression tests |
| Benchmarks against CoreDNS (`cargo xtask bench`) | a level 2 scenario for every plugin and level 3 common setups, see below |
| `kubernetes` + `k8s_external` | every option of CoreDNS 1.15.0 incl. `multicluster`, `zonal`, `apiserver_*` limits, zone transfers, `kubernetes/*` metadata and `coredns_kubernetes_*` metrics ([parity table](docs/PLAN.md#parity-with-coredns-1150-pluginkubernetes-plugink8s_external)); CoreDNS's own tests replay with identical results (130 kubernetes and 38 k8s_external handler cases, transfers, metadata); 57k queries against a live kind cluster match CoreDNS exactly (4 Corefile variants); coredns/ci's end-to-end tests run in CI ([expectations](go/compat/expectations-kind.txt)) |
| Go plugin bridge: CoreDNS plugins without a Rust port run in Go inside the chain (e.g. `route53`; `-bridge.prefer etcd` runs `etcd` in Go instead of its Rust port) | done (M3) |

### Benchmarks

Every plugin has a level 2 scenario: a directory in
[`bench/plugins/`](bench/plugins/) with a Corefile template, fixtures and
queries, often with several cases (cache hits and misses, forward over
UDP/TCP/DoT, zone sizes, regex rewrites, AXFR, TSIG, ...). `cargo xtask
bench` runs each case against CoreDNS 1.15.0 and KernDNS with the same
Corefile and fixtures, servers pinned to 2 cores (4 threads) of a 4-core
laptop (i7-1065G7) and dnsperf on others, and reports the CPU time per query
(also as the part each case adds over a `whoami`-only server), max QPS and
peak RSS.
Plugins without per-query work are listed in
[`bench/plugins/EXEMPT`](bench/plugins/EXEMPT); `cargo xtask bench --check`
(in CI) fails for any other plugin without a scenario. DoQ, DoH3 and gRPC
cases (`quic`, `https3`, `grpc_server`) use `cargo xtask loadgen`, a small
load generator with dnsperf's arguments and output, since dnsperf can't
speak those transports.

**How to read these numbers.** They come from one `cargo xtask bench
--level 2,3 --duration 3 --runs 3` (median of 3 runs per case) on
2026-11-28 on the otherwise quiet laptop (CoreDNS's `whoami` reached 112k
QPS; an earlier run under heavy load from parallel builds reached only 14k
and is not used here). Each cell is CoreDNS → KernDNS, with KernDNS's
change relative to CoreDNS (positive is better for QPS, negative for CPU
and memory). CPU is the whole server's CPU time per query at max load,
including the `whoami`-only baseline. `metadata` is missing: CoreDNS
didn't start in time for that case in this run.

| case | max QPS | CPU µs per query | peak RSS |
|---|---|---|---|
| whoami | 112k → 112k (+0%) | 23.1 → 28.7 (+24%) | 60 → 10 MiB (-83%) |
| acl | 61k → 121k (+99%) | 53.9 → 28.4 (-47%) | 60 → 11 MiB (-82%) |
| acl/block | 46k → 119k (+160%) | 45.8 → 28.1 (-39%) | 57 → 11 MiB (-81%) |
| any | 69k → 40k (-41%) | 35.0 → 29.4 (-16%) | 58 → 11 MiB (-81%) |
| auto | 70k → 125k (+79%) | 56.7 → 31.9 (-44%) | 71 → 20 MiB (-72%) |
| autopath | 42k → 88k (+108%) | 94.7 → 45.5 (-52%) | 70 → 20 MiB (-72%) |
| bufsize | 121k → 191k (+57%) | 22.3 → 18.5 (-17%) | 59 → 10 MiB (-82%) |
| cache | 123k → 136k (+11%) | 22.3 → 26.9 (+21%) | 68 → 18 MiB (-74%) |
| cache/miss | 28k → 40k (+43%) | 88.2 → 49.3 (-44%) | 66 → 18 MiB (-73%) |
| cancel | 106k → 199k (+87%) | 25.4 → 18.3 (-28%) | 60 → 10 MiB (-84%) |
| chaos | 112k → 186k (+67%) | 28.9 → 19.0 (-34%) | 61 → 10 MiB (-83%) |
| dns64 | 81k → 133k (+64%) | 49.1 → 30.0 (-39%) | 71 → 20 MiB (-72%) |
| dnssec | 60k → 100k (+68%) | 66.5 → 39.9 (-40%) | 76 → 28 MiB (-63%) |
| dnssec/cache | 116k → 163k (+41%) | 27.1 → 24.5 (-10%) | 87 → 30 MiB (-65%) |
| dnssec/cold | 22k → 52k (+134%) | 180.9 → 77.4 (-57%) | 75 → 24 MiB (-68%) |
| dnstap | 80k → 176k (+120%) | 34.7 → 22.7 (-35%) | 60 → 18 MiB (-71%) |
| dnstap/forward | 28k → 30k (+10%) | 80.2 → 58.2 (-27%) | 66 → 16 MiB (-75%) |
| dynupdate | 106k → 167k (+58%) | 34.5 → 23.9 (-31%) | 60 → 14 MiB (-77%) |
| dynupdate/update | 3k → 2k (-45%) | 674.6 → 762.9 (+13%) | 63 → 38 MiB (-39%) |
| erratic | 127k → 182k (+43%) | 19.4 → 18.2 (-6%) | 57 → 11 MiB (-80%) |
| errors | 120k → 141k (+18%) | 22.1 → 24.6 (+11%) | 59 → 10 MiB (-83%) |
| etcd | 25k → 18k (-28%) | 102.2 → 117.0 (+14%) | 79 → 24 MiB (-69%) |
| etcd/bridge | 18k → 24k (+33%) | 141.3 → 122.3 (-13%) | 78 → 61 MiB (-21%) |
| file | 72k → 171k (+137%) | 55.3 → 23.4 (-58%) | 73 → 20 MiB (-73%) |
| file/100k | 90k → 163k (+80%) | 44.1 → 24.5 (-44%) | 186 → 71 MiB (-62%) |
| file/8a | 106k → 166k (+57%) | 32.7 → 24.0 (-27%) | 61 → 14 MiB (-77%) |
| file/small | 109k → 164k (+51%) | 31.9 → 24.2 (-24%) | 62 → 13 MiB (-79%) |
| forward | 29k → 29k (+0%) | 64.8 → 51.7 (-20%) | 64 → 15 MiB (-76%) |
| forward/dot | 36k → 33k (-9%) | 85.7 → 92.7 (+8%) | 87 → 22 MiB (-75%) |
| forward/tcp | 41k → 33k (-19%) | 75.5 → 85.1 (+13%) | 64 → 15 MiB (-76%) |
| geoip | 40k → 86k (+114%) | 94.7 → 46.0 (-51%) | 62 → 13 MiB (-79%) |
| grpc | 10k → 10k (+1%) | 142.8 → 105.8 (-26%) | 67 → 24 MiB (-65%) |
| grpc_server | 49k → 26k (-46%) | 63.5 → 66.4 (+5%) | 67 → 15 MiB (-77%) |
| header | 74k → 62k (-16%) | 35.8 → 32.2 (-10%) | 59 → 11 MiB (-81%) |
| hosts | 75k → 60k (-19%) | 36.9 → 32.0 (-13%) | 70 → 23 MiB (-67%) |
| hosts/miss | 51k → 102k (+100%) | 59.7 → 32.3 (-46%) | 71 → 23 MiB (-68%) |
| https | 19k → 28k (+49%) | 171.3 → 69.6 (-59%) | 69 → 16 MiB (-77%) |
| https3 | 29k → 32k (+10%) | 125.2 → 84.5 (-32%) | 74 → 21 MiB (-71%) |
| k8s_external | 58k → 119k (+104%) | 52.5 → 32.9 (-37%) | 77 → 25 MiB (-68%) |
| kubernetes | 68k → 74k (+9%) | 50.8 → 51.1 (+1%) | 77 → 25 MiB (-67%) |
| loadbalance | 43k → 80k (+87%) | 74.4 → 41.0 (-45%) | 63 → 14 MiB (-78%) |
| local | 51k → 70k (+37%) | 50.9 → 35.6 (-30%) | 64 → 11 MiB (-83%) |
| log | 14k → 33k (+137%) | 90.3 → 50.1 (-45%) | 61 → 12 MiB (-80%) |
| log/class-denial | 19k → 32k (+65%) | 70.5 → 49.1 (-30%) | 60 → 11 MiB (-81%) |
| loop | 25k → 40k (+61%) | 49.9 → 29.7 (-41%) | 61 → 7 MiB (-89%) |
| minimal | 26k → 62k (+140%) | 81.5 → 42.5 (-48%) | 72 → 20 MiB (-72%) |
| multisocket | 39k → 71k (+79%) | 44.9 → 27.7 (-38%) | 60 → 10 MiB (-83%) |
| nsid | 26k → 53k (+103%) | 72.6 → 41.3 (-43%) | 63 → 7 MiB (-89%) |
| prometheus | 22k → 67k (+207%) | 75.5 → 32.3 (-57%) | 62 → 11 MiB (-82%) |
| proxyproto | 26k → 75k (+190%) | 55.2 → 27.1 (-51%) | 65 → 11 MiB (-83%) |
| quic | 31k → 36k (+15%) | 86.0 → 52.7 (-39%) | 79 → 19 MiB (-76%) |
| rewrite | 33k → 60k (+85%) | 65.6 → 33.2 (-49%) | 60 → 13 MiB (-78%) |
| rewrite/chain | 25k → 59k (+138%) | 77.1 → 46.5 (-40%) | 62 → 13 MiB (-78%) |
| rewrite/regex | 30k → 39k (+29%) | 73.1 → 57.9 (-21%) | 59 → 13 MiB (-78%) |
| rewrite/suffix | 28k → 81k (+194%) | 69.1 → 36.9 (-47%) | 61 → 12 MiB (-81%) |
| secondary | 38k → 85k (+123%) | 68.9 → 38.4 (-44%) | 72 → 20 MiB (-72%) |
| shed | 37k → 74k (+102%) | 42.3 → 25.2 (-40%) | 58 → 12 MiB (-80%) |
| siit | 30k → 50k (+68%) | 81.6 → 52.3 (-36%) | 60 → 14 MiB (-78%) |
| template | 27k → 67k (+152%) | 85.3 → 52.0 (-39%) | 60 → 14 MiB (-77%) |
| template/rcode | 24k → 82k (+246%) | 83.2 → 43.7 (-47%) | 60 → 14 MiB (-77%) |
| timeouts | 30k → 106k (+249%) | 44.5 → 25.5 (-43%) | 58 → 11 MiB (-81%) |
| tls | 60k → 114k (+90%) | 38.7 → 19.2 (-50%) | 60 → 11 MiB (-81%) |
| trace | 15k → 55k (+264%) | 158.9 → 50.3 (-68%) | 70 → 16 MiB (-77%) |
| transfer | 31k → 60k (+96%) | 75.8 → 38.9 (-49%) | 73 → 20 MiB (-73%) |
| transfer/axfr | 8k → 16k (+106%) | 396.3 → 184.7 (-53%) | 60 → 11 MiB (-81%) |
| tsig | 22k → 65k (+199%) | 101.0 → 39.6 (-61%) | 63 → 12 MiB (-81%) |
| view | 29k → 159k (+457%) | 88.5 → 23.6 (-73%) | 63 → 11 MiB (-82%) |

In 58 of the 67 level 2 cases KernDNS needs less CPU per query than
CoreDNS (median -39%), and in every case less memory (median -77%,
between -21% and -89%). The exceptions:

- **The cheapest chains cost KernDNS more CPU:** `whoami` (+24%: 28.7 vs
  23.1 µs per query at the same 112k QPS), `cache` hits (+21%), `errors`
  (+11%) and `kubernetes` (+1%). With almost no per-query work, KernDNS's
  per-request overhead shows. (In the earlier run under heavy load the
  order was reversed: 48.5 µs for CoreDNS, 29.3 µs for KernDNS.)
- **Some paths with real work:** signed dynamic updates (+13% CPU, -45%
  QPS), forward over TCP and DoT (+13%, +8%), `grpc_server` (+5%, -46%
  QPS) and `etcd` (+14%, -28% QPS).
- **Max QPS is also lower** for `any` (-41%), `header` (-16%) and `hosts`
  (-19%) despite less CPU per query, which points at latency or
  concurrency limits rather than CPU.

These are the next performance work items. The detailed report
(`target/bench/report.md`) also has latency at a fixed rate (half of
CoreDNS's max) per case.

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

Kubernetes at scale (`cargo xtask k8s-bench`, a fake API server serving N
Services with 3 endpoints each; both servers watch it via kubeconfig):

| Services | Sync time CoreDNS → KernDNS | RSS after sync | Peak RSS | Max QPS |
|---:|---|---|---|---|
| 1,000 | 0.69 s → 0.23 s (-67%) | 66 → 19 MiB (-71%) | 78 → 21 MiB (-73%) | 18k → 30k (+67%) |
| 10,000 | 5.6 s → 0.64 s (-89%) | 121 → 77 MiB (-36%) | 148 → 77 MiB (-48%) | 33k → 108k (+227%) |
| 50,000 | 7.8 s → 1.9 s (-76%) | 352 → 178 MiB (-49%) | 495 → 254 MiB (-49%) | 66k → 125k (+89%) |

Level 3, common setups ([`bench/setups/`](bench/setups/)): whole
Corefiles of typical deployments, in the same run as level 2 above
(`cargo xtask bench --level 3`). `kubeadm` is kubeadm's default Corefile
against a fake API server with 1,000 Services and the queries pods send
through the `ndots:5` search path. `split/external` queries the split
horizon setup from another source address (dnsperf `-a 127.0.0.2`), so
the internal view rejects it. The `etcd` setups are CoreDNS's etcd example
against a throwaway etcd with 500 services, all in Rust in KernDNS; the
`bridge` setups are the same Corefiles with KernDNS running `etcd` in Go
through the bridge (`-bridge.prefer etcd`). Both servers answered with the
same response codes in every case.

| setup | max QPS | CPU µs per query | peak RSS |
|---|---|---|---|
| authoritative | 55k → 119k (+115%) | 61.6 → 33.5 (-46%) | 80 → 21 MiB (-74%) |
| bridge | 49k → 36k (-27%) | 63.2 → 69.7 (+10%) | 80 → 56 MiB (-30%) |
| bridge/uncached | 12k → 8k (-36%) | 189.9 → 254.5 (+34%) | 84 → 63 MiB (-25%) |
| etcd | 24k → 54k (+123%) | 81.0 → 47.6 (-41%) | 83 → 23 MiB (-73%) |
| etcd/uncached | 9k → 7k (-16%) | 203.0 → 175.3 (-14%) | 82 → 27 MiB (-68%) |
| forwarder | 28k → 89k (+218%) | 66.6 → 39.2 (-41%) | 99 → 35 MiB (-65%) |
| frontend | 54k → 94k (+75%) | 51.1 → 37.2 (-27%) | 69 → 17 MiB (-76%) |
| frontend/doh | 20k → 40k (+95%) | 132.5 → 81.4 (-39%) | 80 → 22 MiB (-72%) |
| kubeadm | 23k → 56k (+142%) | 126.7 → 64.0 (-49%) | 79 → 28 MiB (-64%) |
| resolver | 27k → 100k (+266%) | 63.7 → 34.2 (-46%) | 68 → 20 MiB (-70%) |
| split | 23k → 84k (+269%) | 92.0 → 40.9 (-56%) | 73 → 20 MiB (-73%) |
| split/external | 48k → 148k (+205%) | 81.8 → 26.9 (-67%) | 74 → 20 MiB (-73%) |

KernDNS needs less CPU per query in 10 of the 12 setups and less memory
in all of them. The exceptions are the two `bridge` setups: running a Go
plugin through the bridge costs more than running it in Go directly (+10%
CPU with a cache in front, +34% without one, where every query crosses
the bridge). With the Rust `etcd` port instead, KernDNS needs 41% less CPU
per query with a cache and 14% less without one.

On a live kind cluster (`--kubeconfig`), an earlier `kubeadm` run gave
147.2 → 74.6 µs per query (-49%) and 73 → 23 MiB (-68%).

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

### Container image

The [`Dockerfile`](Dockerfile) builds an image that replaces CoreDNS's
(`registry.k8s.io/coredns/coredns`) by changing only the `image` field of
kubeadm's `coredns` Deployment:

```sh
kubectl -n kube-system set image deployment/coredns coredns=ghcr.io/mrueg/kerndns:main
# or build it yourself:
docker build -t kerndns .
kind load docker-image --name CLUSTER kerndns
kubectl -n kube-system set image deployment/coredns coredns=kerndns
```

CI builds the image on every PR and pushes it to
`ghcr.io/mrueg/kerndns` on every push to `main` (tags `main`, `latest` and
`sha-<commit>`) and for `v*` tags (the version). Remember that KernDNS is
a prototype: don't put this image in a production cluster.

Like CoreDNS's image, the entrypoint is `/coredns` (an alias of
`/kerndns`), it runs as uid/gid 65532 with `cap_net_bind_service` on the
binary, and the Deployment's `-conf /etc/coredns/Corefile`, probes
(`health` on :8080, `ready` on :8181), metrics on :9153, read-only root
filesystem and dropped capabilities all work unchanged. The base is
distroless `cc` (glibc) instead of `static`, so `-bridge` can load a Go
plugin library; the image is 57 MB (CoreDNS 1.14.6: 77 MB).

Checked on a kind cluster with a copy of kubeadm's Deployment, Service,
ConfigMap (the default Corefile) and RBAC in a test namespace: ready in
seconds, probes and `/metrics` answer, the ConfigMap edit is picked up by
`reload`, a deleted pod goes through `lameduck` and exits, and 47 queries
(services, headless, ExternalName, SRV, pods, PTR, NXDOMAIN, external
names; over UDP and TCP) get the same answers as the cluster's CoreDNS, except
`cluster.local NS`, which names the DNS Service in the server's own
namespace in both.

CI also runs CoreDNS's end-to-end Kubernetes tests
([coredns/ci](https://github.com/coredns/ci), `test/kubernetes`) with this
image as the cluster DNS of a kind cluster, set up the way coredns/ci sets
it up for CoreDNS (one replica, its Deployment and ClusterRole patches, its
test namespaces and workloads).

And it runs Kubernetes' own `[sig-network] DNS` and `[sig-network]
Services` conformance tests (`cargo xtask k8s-conformance`, the `e2e.test`
and `ginkgo` of the Kubernetes release matching the kind node image) with
only the image of kind's kube-system/coredns Deployment replaced
(`kubectl set image`), kubeadm's Corefile unchanged.

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
fuzz/         cargo-fuzz targets: Corefile setup, the request path, the Go bridge
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
cargo xtask etcd-difftest               # same etcd records in CoreDNS and kerndns (--bridge: Go etcd in kerndns)
cargo xtask bench                       # CoreDNS vs kerndns with dnsperf, every scenario
cargo xtask bench --plugin cache,forward  # level 2 cases of some plugins (+ whoami baseline)
cargo xtask bench --level 3             # common setups only
cargo xtask bench --check               # every plugin has a scenario (no dnsperf needed)
cargo xtask loadgen -m doq -p 853 -d queries.txt -l 10  # DoQ/DoH3/gRPC load (dnsperf-style output)
cargo xtask k8s-cases                   # regenerate the upstream kubernetes test cases (Go)
cargo xtask plugin-cases                # regenerate the upstream plugin table tests (Go), see docs/plugin-cases.md
cargo xtask k8s-bench                   # kubernetes plugin at 1k/10k/50k services
# live-cluster comparison (workloads in namespaces testns/other):
kubectl --context CTX apply -f bench/k8s/workloads.yaml
cargo xtask k8s-difftest --context CTX
cargo xtask bench --scenario kubeadm --kubeconfig KUBECONFIG  # kubeadm setup against the live cluster
kubectl --context CTX delete ns testns other
```

`compat-test` builds `kerndns` and compiles CoreDNS's `test` package with a
[Go overlay](go/compat/) that replaces the server-start helpers with ones that
run the `kerndns` binary. The upstream test files run unmodified. Each test
runs in its own process, and the results are compared with
[`go/compat/expectations.txt`](go/compat/expectations.txt):

- **pass**: must keep passing.
- **xfail**: fails today, with the reason; the run fails when one starts passing, so it gets promoted.
- **skip**: can't apply to KernDNS (tests Go internals or CoreDNS's Go source), with the reason.

A test only counts as passing if it actually started `kerndns`. Tests that
pass without ever starting the server are classified as `skip`. A test's
`Instance.Restart` reloads the running `kerndns` in place (`-control`), and
the tests whose plugins live in the Go test binary get them through a Go
bridge built from [`go/bridge/testplugins`](go/bridge/testplugins/).

### Dependency checks

```sh
cargo install cargo-deny --locked
cargo deny --all-features --locked check                                  # workspace
cargo deny --all-features --locked --manifest-path fuzz/Cargo.toml check  # fuzz crate
(cd go/bridge && go run golang.org/x/vuln/cmd/govulncheck@latest -tags allplugins ./...)
(cd go/difftest && go run golang.org/x/vuln/cmd/govulncheck@latest ./...)
```

[`deny.toml`](deny.toml) checks RustSec advisories (vulnerable, unmaintained,
unsound or yanked crates), licenses (permissive ones compatible with
Apache-2.0), duplicate crate versions (warnings) and sources (crates.io
only). govulncheck checks the Go bridge with every in-tree CoreDNS plugin
([`go/bridge/allplugins.go`](go/bridge/allplugins.go), with the dependency
versions the bridge selects; CoreDNS itself stays pinned to the submodule)
and the difftest server. The [Dependencies](.github/workflows/deps.yml)
workflow runs both on pull requests, pushes to main and every Monday, so new
advisories show up without a code change.

### Fuzzing

[`fuzz/`](fuzz/) has [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
(libFuzzer) targets; they need a nightly toolchain:

| target | what it feeds |
|---|---|
| `corefile` | arbitrary Corefiles through the lexer, the dispenser, the parser and every plugin's setup (`config::load`, no sockets, no startup hooks) |
| `wire` | arbitrary packets through the server's request path (`udp::handle` over UDP/TCP, or `unpack_request` + `answer` as DoH, DoH3, DoQ and gRPC do) with a chain of acl, header, rewrite, cache, loadbalance, template, file, tsig, minimal, hosts, dns64, chaos, ... ([`fuzz/fixtures/Corefile.wire`](fuzz/fixtures/Corefile.wire)) |
| `bridge` | the Rust side of the Go bridge without the Go library: arbitrary callback sequences (responses, calls to next, results), the plugin list, and directive rendering (rendered tokens must lex back to the same tokens) |

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run wire corpus/wire seeds/wire -- -max_total_time=600 -close_fd_mask=1 -jobs=2
```

Seeds in `fuzz/seeds/` come from CoreDNS's READMEs and integration test
Corefiles and from hand-built queries; `corpus/` and `artifacts/` are not
committed. CI builds the targets and runs each for 60 seconds.

## License

Apache-2.0, the same as CoreDNS.
