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
| Plugins | `acl`, `any`, `auto`, `autopath`, `bind`, `bufsize`, `cache`, `cancel`, `chaos`, `debug`, `dns64`, `dnssec`, `dnstap`, `dynupdate`, `erratic`, `errors`, `etcd`, `file`, `forward` (UDP/TCP/DoT), `geoip`, `grpc`, `grpc_server`, `header`, `health`, `hosts`, `https`, `https3`, `k8s_external`, `kubernetes`, `loadbalance`, `local`, `log`, `loop`, `metadata`, `minimal`, `multisocket`, `nsid`, `on`, `pprof`, `prometheus`, `proxyproto`, `quic`, `ready`, `reload`, `rewrite`, `root`, `secondary`, `shed`, `sign`, `siit`, `template`, `timeouts`, `tls`, `trace`, `transfer`, `tsig`, `view`, `whoami` |
| Metrics with CoreDNS's names, labels and buckets (text and protobuf exposition) | done |
| CoreDNS integration tests against KernDNS | 108 pass, 2 expected failures, 12 skipped (Go internals, checks of the Go source, a shared in-process metrics registry), see [expectations](go/compat/expectations.txt); harness check: real CoreDNS passes 120 of 122 (`TestDynUpdateKeaLifecycle` skips without Kea; `TestQUICReloadDoesNotPanic` is flaky on CoreDNS itself; `TestEtcdStubAndProxyLookup` expects an outdated address for example.com) |
| Differential test against CoreDNS (`file` zones from CoreDNS's tests, 15k+ queries) | no differences |
| Differential test of `etcd` against CoreDNS (one throwaway etcd: 500 services plus the unit tests' records, leases, weights, out-of-zone targets, broken JSON; 2 Corefiles, 32k queries) | no differences |
| CoreDNS's plugin table tests: 51 plugins' test tables extracted from the Go source (`cargo xtask plugin-cases`) and replayed through KernDNS | 1,197 of 1,962 rows pass, 73 expected failures (features not ported yet), the rest skipped with a reason; see [docs/plugin-cases.md](docs/plugin-cases.md) |
| CoreDNS's end-to-end Kubernetes tests ([coredns/ci](https://github.com/coredns/ci) `test/kubernetes`) with the KernDNS image as a kind cluster's DNS (CI job `kind`, with CoreDNS's own image as a control) | all 13 that exercise the cluster DNS pass; 2 skipped (one depends on the CI runner's resolv.conf and fails for CoreDNS too, one tests an in-process Go CoreDNS), see [expectations](go/compat/expectations-kind.txt) |
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
2026-11-27, on a laptop where four parallel builds were running at the
same time. Under that load **max QPS is not reliable**: CoreDNS's `whoami`
reached only 14k QPS where it reaches about 110k on the quiet machine, so
the QPS column mostly measures the noise. **CPU time per query and peak
memory** hold up much better under load and are the numbers to compare.
Each cell is CoreDNS → KernDNS, with KernDNS's change relative to CoreDNS
(negative is better for CPU and memory, positive for QPS). CPU is the whole
server's CPU time per query at max load, including the `whoami`-only
baseline of 48.5 µs (CoreDNS) and 29.3 µs (KernDNS).

| case | CPU µs per query | peak RSS | max QPS (unreliable) |
|---|---|---|---|
| whoami | 48.5 → 29.3 (-40%) | 58 → 13 MiB (-78%) | 14k → 25k (+76%) |
| acl | 63.5 → 29.0 (-54%) | 61 → 13 MiB (-79%) | 32k → 43k (+31%) |
| acl/block | 46.0 → 30.4 (-34%) | 60 → 12 MiB (-80%) | 21k → 30k (+38%) |
| any | 50.8 → 27.4 (-46%) | 60 → 12 MiB (-80%) | 36k → 68k (+88%) |
| auto | 86.1 → 41.0 (-52%) | 74 → 20 MiB (-73%) | 12k → 63k (+423%) |
| autopath | 132.8 → 73.4 (-45%) | 72 → 20 MiB (-73%) | 25k → 41k (+63%) |
| bufsize | 47.1 → 28.0 (-41%) | 61 → 12 MiB (-81%) | 39k → 91k (+131%) |
| cache | 41.0 → 30.9 (-24%) | 67 → 18 MiB (-73%) | 62k → 53k (-14%) |
| cache/miss | 105.7 → 72.0 (-32%) | 67 → 18 MiB (-73%) | 28k → 14k (-49%) |
| cancel | 51.5 → 29.0 (-44%) | 62 → 11 MiB (-82%) | 23k → 50k (+113%) |
| chaos | 64.7 → 30.1 (-53%) | 60 → 12 MiB (-81%) | 15k → 34k (+121%) |
| dns64 | 126.5 → 72.0 (-43%) | 73 → 19 MiB (-74%) | 13k → 17k (+33%) |
| dnssec | 117.2 → 88.8 (-24%) | 79 → 28 MiB (-65%) | 27k → 21k (-21%) |
| dnssec/cache | 59.3 → 48.6 (-18%) | 91 → 30 MiB (-67%) | 29k → 41k (+40%) |
| dnssec/cold | 520.2 → 196.4 (-62%) | 79 → 22 MiB (-73%) | 2k → 7k (+296%) |
| dnstap | 84.6 → 39.9 (-53%) | 61 → 20 MiB (-68%) | 9k → 30k (+232%) |
| dnstap/forward | 153.3 → 103.2 (-33%) | 65 → 20 MiB (-69%) | 6k → 6k (+6%) |
| dynupdate | 83.3 → 70.1 (-16%) | 59 → 13 MiB (-78%) | 14k → 8k (-41%) |
| dynupdate/update | 1709.2 → 1098.4 (-36%) | 66 → 37 MiB (-43%) | 0k → 1k (+119%) |
| erratic | 43.3 → 27.6 (-36%) | 58 → 11 MiB (-80%) | 25k → 106k (+325%) |
| errors | 51.6 → 27.8 (-46%) | 59 → 11 MiB (-81%) | 41k → 77k (+87%) |
| file | 76.3 → 51.7 (-32%) | 72 → 18 MiB (-74%) | 46k → 57k (+23%) |
| file/100k | 149.5 → 73.5 (-51%) | 180 → 70 MiB (-61%) | 7k → 20k (+167%) |
| file/8a | 109.2 → 60.6 (-45%) | 60 → 12 MiB (-80%) | 10k → 36k (+267%) |
| file/small | 99.6 → 60.8 (-39%) | 59 → 12 MiB (-80%) | 19k → 26k (+37%) |
| forward | 169.8 → 113.3 (-33%) | 64 → 15 MiB (-77%) | 9k → 4k (-51%) |
| forward/dot | 154.3 → 129.2 (-16%) | 78 → 20 MiB (-74%) | 17k → 14k (-13%) |
| forward/tcp | 195.9 → 135.6 (-31%) | 62 → 14 MiB (-77%) | 6k → 8k (+31%) |
| geoip | 180.3 → 83.8 (-53%) | 62 → 12 MiB (-80%) | 10k → 11k (+3%) |
| grpc | 157.0 → 100.1 (-36%) | 66 → 23 MiB (-66%) | 4k → 5k (+21%) |
| grpc_server | 93.7 → 82.7 (-12%) | 68 → 15 MiB (-78%) | 9k → 8k (-12%) |
| header | 53.1 → 33.8 (-36%) | 60 → 10 MiB (-83%) | 16k → 23k (+43%) |
| hosts | 65.5 → 47.2 (-28%) | 70 → 22 MiB (-68%) | 12k → 21k (+84%) |
| hosts/miss | 69.9 → 31.9 (-54%) | 70 → 23 MiB (-68%) | 15k → 34k (+132%) |
| https | 184.7 → 74.4 (-60%) | 71 → 15 MiB (-78%) | 7k → 13k (+89%) |
| https3 | 156.0 → 82.8 (-47%) | 78 → 29 MiB (-63%) | 8k → 12k (+40%) |
| k8s_external | 69.3 → 41.2 (-41%) | 75 → 24 MiB (-68%) | 17k → 35k (+108%) |
| kubernetes | 70.3 → 40.4 (-43%) | 75 → 24 MiB (-68%) | 33k → 68k (+105%) |
| loadbalance | 65.5 → 32.8 (-50%) | 59 → 13 MiB (-77%) | 38k → 91k (+139%) |
| local | 46.1 → 27.3 (-41%) | 61 → 11 MiB (-81%) | 50k → 81k (+62%) |
| log | 64.1 → 25.2 (-61%) | 61 → 12 MiB (-80%) | 28k → 92k (+223%) |
| log/class-denial | 59.9 → 38.9 (-35%) | 59 → 12 MiB (-80%) | 31k → 75k (+140%) |
| loop | 35.8 → 24.1 (-33%) | 61 → 11 MiB (-82%) | 68k → 144k (+113%) |
| metadata | 22.1 → 23.7 (+7%) | 58 → 10 MiB (-82%) | 121k → 146k (+21%) |
| minimal | 42.7 → 38.0 (-11%) | 71 → 19 MiB (-73%) | 93k → 101k (+9%) |
| multisocket | 44.0 → 22.9 (-48%) | 60 → 10 MiB (-83%) | 50k → 144k (+189%) |
| nsid | 63.5 → 33.6 (-47%) | 62 → 11 MiB (-82%) | 29k → 45k (+53%) |
| prometheus | 74.8 → 30.7 (-59%) | 59 → 12 MiB (-79%) | 19k → 60k (+210%) |
| proxyproto | 41.3 → 25.5 (-38%) | 65 → 11 MiB (-83%) | 63k → 56k (-11%) |
| quic | 83.6 → 43.3 (-48%) | 78 → 24 MiB (-70%) | 26k → 30k (+18%) |
| rewrite | 63.4 → 31.0 (-51%) | 62 → 13 MiB (-79%) | 23k → 69k (+198%) |
| rewrite/chain | 75.4 → 46.0 (-39%) | 63 → 13 MiB (-80%) | 20k → 46k (+133%) |
| rewrite/regex | 70.9 → 58.9 (-17%) | 62 → 13 MiB (-80%) | 25k → 35k (+42%) |
| rewrite/suffix | 62.1 → 28.1 (-55%) | 61 → 11 MiB (-82%) | 41k → 130k (+221%) |
| secondary | 66.3 → 30.5 (-54%) | 72 → 21 MiB (-71%) | 40k → 122k (+208%) |
| shed | 30.3 → 18.4 (-39%) | 62 → 12 MiB (-81%) | 80k → 160k (+100%) |
| siit | 46.6 → 30.7 (-34%) | 62 → 14 MiB (-77%) | 61k → 113k (+87%) |
| template | 66.0 → 51.2 (-22%) | 59 → 14 MiB (-77%) | 59k → 74k (+26%) |
| template/rcode | 72.7 → 39.8 (-45%) | 62 → 14 MiB (-78%) | 52k → 93k (+80%) |
| timeouts | 32.0 → 30.5 (-5%) | 60 → 11 MiB (-82%) | 82k → 98k (+19%) |
| tls | 35.9 → 29.4 (-18%) | 60 → 11 MiB (-81%) | 100k → 115k (+14%) |
| trace | 111.0 → 70.6 (-36%) | 82 → 15 MiB (-81%) | 34k → 30k (-11%) |
| transfer | 80.9 → 46.6 (-42%) | 73 → 18 MiB (-75%) | 42k → 51k (+23%) |
| transfer/axfr | 352.9 → 137.9 (-61%) | 60 → 11 MiB (-82%) | 11k → 29k (+165%) |
| tsig | 81.0 → 40.1 (-50%) | 61 → 10 MiB (-84%) | 48k → 84k (+75%) |
| view | 84.6 → 29.7 (-65%) | 62 → 11 MiB (-82%) | 44k → 117k (+165%) |
| etcd⁴ | 184.5 → 110.2 (-40%) | 78 → 25 MiB (-68%) | 7k → 9k (+29%) |
| etcd/bridge⁴ (KernDNS: Go etcd through the bridge) | 189.4 → 219.5 (+16%) | 80 → 63 MiB (-21%) | 8k → 8k (+0%) |

⁴ From a separate run of only the etcd cases against a throwaway etcd with
500 services (the full run predates the Rust `etcd` port). etcd's latency
dominates and max QPS swings with it.

KernDNS uses less CPU per query than CoreDNS in every level 2 case except
`metadata` (+7%, within the noise of a 22 µs case) and `etcd` through the
Go bridge. It needs a sixth to a third of CoreDNS's peak memory in most
cases, and about 40-60% in the heaviest ones (signed dynamic updates, the
100k-name zone, DoH3). The detailed report
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
Corefiles of typical deployments, run the same way and in the same run as
level 2 above (`cargo xtask bench --level 3`), so the same caveat about max
QPS applies. `kubeadm` is kubeadm's default Corefile against a fake API
server with 1,000 Services and the queries pods send through the `ndots:5`
search path. `split/external` queries the split horizon setup from
another source address (dnsperf `-a 127.0.0.2`), so the internal view
rejects it. The `bridge` setups are CoreDNS's etcd example against a
throwaway etcd with 500 services, with KernDNS running `etcd` in Go
through the bridge and the rest in Rust; the `etcd` setups⁵ are the same
Corefiles with the Rust `etcd` port. Both servers answered with the same
response codes in every case.

| setup | CPU µs per query | peak RSS | max QPS (unreliable) |
|---|---|---|---|
| authoritative | 74.2 → 53.5 (-28%) | 81 → 21 MiB (-75%) | 45k → 73k (+62%) |
| bridge | 70.5 → 74.8 (+6%) | 75 → 57 MiB (-24%) | 44k → 41k (-6%) |
| bridge/uncached | 222.0 → 227.1 (+2%) | 81 → 66 MiB (-19%) | 10k → 7k (-32%) |
| forwarder | 72.2 → 40.2 (-44%) | 90 → 35 MiB (-61%) | 24k → 58k (+146%) |
| frontend | 50.6 → 29.6 (-41%) | 68 → 15 MiB (-78%) | 48k → 110k (+130%) |
| frontend/doh | 191.4 → 77.1 (-60%) | 76 → 22 MiB (-71%) | 12k → 24k (+103%) |
| kubeadm | 111.7 → 67.3 (-40%) | 77 → 27 MiB (-64%) | 35k → 40k (+14%) |
| resolver | 65.3 → 33.4 (-49%) | 73 → 19 MiB (-74%) | 24k → 114k (+375%) |
| split | 95.8 → 26.5 (-72%) | 76 → 19 MiB (-75%) | 21k → 127k (+490%) |
| split/external | 88.3 → 32.9 (-63%) | 75 → 20 MiB (-74%) | 37k → 121k (+224%) |
| etcd⁵ | 78.5 → 44.8 (-43%) | 72 → 22 MiB (-69%) | 25k → 65k (+160%) |
| etcd/uncached⁵ | 170.7 → 101.2 (-41%) | 84 → 26 MiB (-69%) | 13k → 22k (+69%) |

⁵ From the separate etcd run (see ⁴). With every query reading etcd, the
Rust port needs about 40% less CPU per query than CoreDNS. Through the
bridge, KernDNS uses about as much CPU per query as all-Go CoreDNS: the
Go plugin's cost plus the bridge's hand-offs.

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
