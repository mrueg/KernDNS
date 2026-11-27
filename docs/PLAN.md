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
  uses hickory-proto for messages and hickory-resolver/recursor inside
  plugins such as `forward`. The listeners (UDP, TCP, DoT, DoH, DoH3, DoQ,
  gRPC), request routing and the chain are KernDNS's own.
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
crates/server     Corefile -> chains -> listeners (dns, tls, https, https3, quic, grpc), dispatch  (done)
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
char* kb_directives(void);                    // JSON, the bridge's dnsserver.Directives
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
and the affinity check when a Corefile loads. Out-of-tree plugins work
too: a directive that the bridge's `dnsserver.Directives` adds (as a
CoreDNS build with that plugin in `plugin.cfg` would) joins KernDNS's
execution order at the same place (interface version 2, `kb_directives`).

- `cargo xtask compat-test` runs CoreDNS's `TestReloadUnreadyPlugin` and
  `TestReloadTwoServerBlocksUnreadyPlugin`, whose never-ready plugins live
  in the test binary, with a bridge holding copies of them
  (`go/bridge/testplugins/unready`, built automatically): KernDNS's
  `ready` sees their `Ready()` through the bridge, also after a reload.

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

## Encrypted listeners (M4)

Every transport CoreDNS serves has a KernDNS listener, all on the same
dispatch path (one parse, one encode per response) and all kept across
reloads like the plain DNS ones:

| Scheme | Listener | Crates | Limits plugin |
|---|---|---|---|
| `tls://` | DoT | tokio-rustls | `timeouts` |
| `https://` | DoH, HTTP/1.1 and HTTP/2 | hyper | `https` (`max_connections` 200, `max_streams` 250) |
| `https3://` | DoH over HTTP/3 | quinn, h3, h3-quinn | `https3` (`max_connections` 200, `max_streams` 256) |
| `quic://` | DoQ, RFC 9250 | quinn | `quic` (`max_connections` 200, `max_streams` 256, `worker_pool_size` 1024) |
| `grpc://` | CoreDNS's `DnsService` over HTTP/2, h2c without `tls` | hyper | `grpc_server` (`max_connections` 200, `max_streams` 256) |

- **Crates.** quinn (with rustls and ring, the provider the `tls` plugin
  already uses) is the maintained Rust QUIC stack; h3/h3-quinn are its HTTP/3
  layer (hyper has none). Together they add 11 small crates to the lock file
  (quinn's proto and UDP parts, h3, and their helpers).
  gRPC is a single unary method with a one-field message, so it is served on
  hyper's HTTP/2 server directly (length-prefixed frame, hand-written
  protobuf, `grpc-status` trailers, grpc-go's status codes and messages)
  instead of pulling in tonic, prost, tower and a protobuf build step.
- **Behaviour taken from CoreDNS:** ALPN (`doq`, `h3`, `h2`); DoQ protocol
  errors close the connection with code 2, a stalled or reset stream is reset
  with code 1 after the read timeout and the connection lives on, one
  response per stream followed by FIN; connections beyond `max_connections`
  are closed with code 0 (DoQ) or `H3_EXCESSIVE_LOAD` (DoH3), or wait in the
  accept queue before the TLS handshake (DoH, gRPC); queries are read with
  miekg/dns's default accept policy (`dnsutil.UnpackRequest`), so responses,
  UPDATEs and multi-question messages are protocol errors, HTTP 400s or gRPC
  errors rather than answers; DoQ and DoH3 clients count as `udp` (CoreDNS
  derives the protocol from the remote address type), so `whoami` says
  `_udp`, answers are truncated to the EDNS size and metrics say
  `proto="udp"`; `coredns_dns_quic_responses_total`,
  `coredns_dns_https_responses_total` and `coredns_dns_https3_responses_total`
  are counted the same way (including CoreDNS's habit of counting a client's
  normal DoQ connection close as `0x1`). Like CoreDNS, the listener plugins
  only apply to a block's first key, except `https`'s `max_streams` and
  `quic`'s `max_connections`, and conflicting DoH `max_streams` on one
  listener are an error.
- **Checked against CoreDNS** with a Go client (quic-go, http3, grpc-go) and
  curl (nghttp2, ngtcp2/nghttp3) on the same Corefile: status codes, headers,
  error codes, truncation, gRPC errors and metrics match. Remaining
  differences: KernDNS compresses names (responses are shorter), parse errors
  in gRPC error messages are worded by hickory rather than miekg/dns, HTTP/3
  doesn't announce datagram support, and when a DoQ request gets no answer
  KernDNS still ends the stream (CoreDNS leaves it open).
- **Not yet:** settings changed by a reload (certificates, limits) don't apply
  to listeners that are kept, as for DoT and DoH.

### ACME certificates (`tls { acme ... }`)

The `tls` plugin obtains and renews certificates with ACME like CoreDNS
1.15 (`plugin/tls/acme.go`), with the same syntax (`acme`, `email`, `ca`,
`storage`, `ca_root`, `resolver`), defaults (Let's Encrypt production,
`.coredns/acme` below the root) and setup errors. CoreDNS delegates to
certmagic; KernDNS uses [instant-acme](https://crates.io/crates/instant-acme)
for the protocol (with ring, hyper-rustls and rcgen; no OpenSSL, no
aws-lc-rs) and implements the rest itself:

- **DNS-01 only.** The first ACME block adds a challenge handler (directive
  `tls`, so it runs early) to every server block, like
  `AddPluginToAllServerBlocks`; it answers `_acme-challenge` TXT queries
  (one question, class IN) for pending challenges and passes everything
  else on. Challenge state is local to the process.
- **Lifecycle.** Management starts after all listeners are up (startup
  hook): stored certificates are loaded, then a task per configuration
  obtains missing certificates and renews them when a third of their
  lifetime is left, checking at least every 10 minutes and retrying failures
  with growing waits (1 minute up to 6 hours). Listeners resolve the
  certificate per handshake (SNI, exact name then wildcard, the first
  domain without SNI; unmanaged names fail the handshake), so DoT, DoH,
  DoH3, DoQ and gRPC use a renewed certificate without a restart. A
  listener kept across a reload keeps its TLS config, which reads the same
  certificate store as the new instance's manager, so renewals keep
  applying. Blocks with identical ACME options share one manager and TLS
  config; a domain in two different configurations is an error.
- **Storage** uses certmagic's file layout and formats
  (`certificates/<issuer>/<name>/<name>.crt|.key|.json`,
  `acme/<issuer>/users/<email>/<user>.key|.json`), so KernDNS and CoreDNS
  can share a directory. KernDNS writes PKCS#8 keys (certmagic reads them)
  and reads certmagic's SEC1 ECDSA keys.
- **`ca_root`** is added to the system roots for the ACME server. A server
  certificate that is itself in `ca_root` is accepted for its names, as Go
  accepts it (webpki refuses a self-signed CA certificate as the server's
  own, which is what Go's `httptest` servers use).
- **`resolver`** resolves the ACME server's name with A/AAAA queries over
  UDP to that address.

Like certmagic, each domain gets its own certificate. Not supported
(certmagic features CoreDNS's syntax doesn't expose, or that KernDNS
leaves out): On-Demand TLS, OCSP stapling, ACME Renewal Information (ARI), storage
locks for several processes sharing a directory, the fallback to the
Let's Encrypt staging CA after failures, External Account Binding, and
key types other than ECDSA P-256. Accounts are only ECDSA P-256 keys.
Validity of a `ca_root`-pinned server certificate is not checked.
CoreDNS logs certmagic's structured messages; KernDNS logs its own
(`obtaining certificate for "..."`, `certificate obtained successfully`,
errors with the retry time).

## Plugin waves

| Wave | Plugins |
|---|---|
| M0 | `whoami`, `log`, `errors`, `debug`, `bind`, `root` (done) |
| 1: minimal server | `file`, `health`, `ready`, `prometheus`, `forward`, `cache`, `hosts`, `reload`, `loop`, `chaos` (done) |
| 2: Kubernetes | `kubernetes`, `k8s_external` (done) |
| 3: authoritative | `file`, `auto`, `secondary`, `transfer`, `any`, `minimal`, `loadbalance`, `local`, `tsig` (done) |
| 4: policy and rewriting | `rewrite`, `template`, `acl`, `metadata`, `view`, `cancel`, `timeouts`, `header`, `dns64`, `autopath`, `nsid`, `tls` (done) |
| 5: DNSSEC and the rest | `dnssec`, `sign`, `dnstap`, `grpc`, `siit`, `shed`, `proxyproto`, `on`, `pprof`, `geoip`, `trace` (done) |

Through the Go bridge until someone needs a port: `etcd`, `route53`,
`clouddns`, `azure`, third-party plugins.

`tls`, `tsig`, `header` and `transfer` are ported (with DoT and DoH
listeners), and so are `secondary` (with RFC 9432 catalog zones) and `dynupdate`
(its database is KernDNS's own file format, replaced atomically per commit,
instead of bbolt). `auto` loads zones from a directory and rescans it with
the `file` zone code, `multisocket` sets the number of `SO_REUSEPORT`
servers (UDP socket and TCP listener each) per address, and the listener
plugins `https`, `https3`, `quic` and `grpc_server` come with DoH3, DoQ and
gRPC listeners (see above). The upstream tests still failing are listed with
their reasons in `go/compat/expectations.txt`.

`grpc` forwards queries to CoreDNS's `DnsService` with a gRPC client of
its own on hyper's HTTP/2 client, the counterpart of the `grpc://`
listener and sharing its protobuf code (`kerndns_core::protobuf`): one
multiplexed connection per upstream (h2c, or TLS with ALPN `h2` from
`tls`/`tls_servername`), redialed when it breaks, `grpc-timeout` from the
5 s budget, grpc-go's status codes and messages, `NotFound` answered as
NXDOMAIN, `unix://` upstreams and resolv.conf files. `policy` and
`except` are shared with `forward` (`forward::policy`); like CoreDNS there
are no health checks. CoreDNS and KernDNS fronts, each forwarding to a
CoreDNS and a KernDNS `grpc://` backend (h2c and TLS), give identical
answers (NOERROR, NXDOMAIN, REFUSED, `except`, DNSSEC OK, TCP clients) and
identical `coredns_grpc_*` metrics; an unreachable upstream is a quick
SERVFAIL in both. Deviation: an upstream with a scheme other than `dns://`
or `unix://` (`tls://…`, `grpc://…`) is a setup error; CoreDNS accepts it
and then fails every query.

`dnstap` writes dnstap messages over Frame Streams to unix, TCP and TLS
sinks (a queue of 10,000 messages times the queue multiple, dropped
messages logged every 10 s, reconnects, `skipverify`) or to sinks that connect to it
(`listen`, with `tls CERT KEY [CA]`), with `full`, `identity`, `version`
and `extra` (placeholders and `{/metadata}`). Other plugins log through
the block's `dnstap::Taps` (CoreDNS's `*dnstap.Dnstap` handler lookup);
`forward` sends FORWARDER_QUERY/FORWARDER_RESPONSE from its upstream
socket. The protobuf messages and the bidirectional Frame Streams
handshake (READY/ACCEPT/START, STOP/FINISH) are written by hand: the
crates.io options are `framestream` (a blocking `std::io::Write` encoder
without the READY/ACCEPT/FINISH handshake CoreDNS's encoder does) and
`dnstap` (built on it, mio and rust-protobuf with build-time codegen).
Compared with CoreDNS through a golang-dnstap sink (outgoing unix socket
and `listen` over TCP, UDP and TCP clients, forwarded NOERROR/NXDOMAIN/
DNSSEC answers, a chain error answered by the server): the same messages,
fields and DNS payloads, except the `version` field (`KernDNS-0.1.0`
instead of `CoreDNS-1.15.0`, as for `chaos`). Like CoreDNS, the
CLIENT_RESPONSE carries the response as the client gets it (EDNS echoed,
truncated over UDP); KernDNS emits it once the chain returns rather than
inside the write, so `extra` sees metadata set later in the chain the way
CoreDNS's lazily evaluated metadata does.

`dnssec` and `sign` sign with ring, the crypto library hickory-proto
(`dnssec-ring`) and rustls already use: ECDSA P-256/P-384, Ed25519 and
RSASHA256/RSASHA512 (2048 to 8192 bits). ring signs neither RSASHA1 nor
shorter RSA keys, so such keys are refused at startup with an error instead
of answering unsigned, and `key aws_secretsmanager` is not supported. RRSIGs
are made with hickory's canonical encoding (`TBS`) and checked in the unit
tests with hickory's verifier for every algorithm; `sign`'s output passes
`ldns-verify-zone`, and `cargo xtask difftest --dnssec` serves every `file`
test zone signed on the fly by both servers, compares the answers without
signature bytes and times, and verifies every RRSIG of both with the same
validator (miekg/dns).

More wave 5 ports:

- `siit` synthesizes A records from AAAA records in its IPv6 prefix or
  explicit address mappings (RFC 6052, RFC 7757). Its internal AAAA lookup
  is marked (`Context::synthesis`), and the mark travels with every
  internal lookup made under it, so `siit` and `dns64` never re-enter each
  other, as in CoreDNS.
- `shed`: UDP responses go through a bounded stack per socket (depth
  1024, oldest evicted, newest sent first) and one writer task; while a
  socket's stack is full its queries are dropped before the chain, counted
  in `coredns_shed_dropped_total{server, reason}`. The listener installs
  the writer when it binds the socket (`UdpDecorator`, CoreDNS's
  `UDPDecorateWriterFunc`), so adding or removing `shed` takes a restart
  (a reload warns). Tokio has no equivalent of Go's per-socket write mutex
  limit; the plugin bounds the same backlog.
- `proxyproto`: PROXY v1/v2 headers parsed with go-proxyproto's rules and
  error messages (`kerndns_core::proxyproto`). UDP takes v2 headers in
  front of the query, with Spectrum-style `udp_session_tracking`; TCP
  takes v1 or v2 before the first message. The client address plugins
  see is the header's source on `dns://`, `tls://`, `https://` and
  `grpc://`; `tlv_metadata` publishes `proxyproto/tlv` for `dns://` and
  `tls://`. Not supported yet: `quic://` and `https3://`. Settings are
  fixed when a listener starts (a reload that changes them warns).
- `on` (caddy's `onevent`): `startup` commands run after the server
  starts and after every reload, `shutdown` commands on SIGTERM/SIGINT,
  `&` runs one in the background, `certrenew` is accepted and never fires.
  A reload replaces the hooks; caddy keeps adding them, so with the
  `reload` plugin CoreDNS reruns the startup commands of every
  configuration loaded so far.
- `pprof` keeps CoreDNS's syntax and errors, but there is no Go runtime to
  profile: `/debug/pprof/profile?seconds=N` returns a CPU profile in
  pprof's (gzipped protobuf) format, sampled at 100 Hz with the `pprof`
  crate, which `go tool pprof` reads, and `/debug/pprof/cmdline` the
  command line. Go-only profiles (heap, goroutine, block, mutex, trace,
  ...) answer 404; `block` is accepted and logs a warning.
- `geoip` reads `.mmdb` files with the `maxminddb` crate, accepts the
  database types geoip2-golang does and sets the same labels; its tests
  use CoreDNS's fixture databases. Like Go's decoder it accepts any
  unsigned width for numbers (the crate's own GeoIP2 structs reject the
  fixtures), and an IPv4 `edns-subnet` is looked up in its IPv4-mapped
  form, as CoreDNS does.
- `trace` has its own small reporters instead of the Zipkin and Datadog
  SDKs: Zipkin gets a `servedns` server span per sampled query with
  CoreDNS's tags and a child span per plugin (from `next_or_failure`, like
  `plugin.NextOrFailure`), as v2 JSON in batches like zipkin-go's HTTP
  reporter (`zipkin_max_*`); Datadog gets the `servedns` span (no plugin
  spans, as in CoreDNS) as JSON on the agent's `/v0.4/traces`. Not
  supported: continuing a trace from a DoH request's B3 headers;
  `client_server` has no effect.

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
   `Instance.Restart` reloads the same `kerndns` process in place: the
   helpers' input has its own caddy server type, `kerndns -control` reads
   each new Corefile from stdin and reports the new listeners or the
   error, and a failed reload keeps the old configuration, as in CoreDNS.
   `chaos` reports the test binary's `caddy.AppName-caddy.AppVersion`
   through `$KERNDNS_CHAOS_VERSION`.
2. **`coredns/ci` end-to-end tests** (kind-based, including Kubernetes):
   a nightly job with the KernDNS image.
3. **Plugin unit tests:** the table tests from each plugin's `*_test.go` are
   ported to Rust, and each plugin lists which upstream files it covers.
4. **Differential testing** (`cargo xtask difftest`): same Corefile and
   fixtures against CoreDNS and KernDNS, a query corpus including fuzzed
   queries, diffs normalised for TTL and RRset order. A plugin becomes the
   default Rust implementation only after it passes.
5. **Fuzzing** (`fuzz/`, cargo-fuzz, done): the Corefile parser, dispenser
   and every plugin's setup; the wire request path with a representative
   chain; the Rust side of the bridge's message handling (callbacks from Go,
   the plugin list, directive rendering). CI runs each target for 60 s.

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
- **Level 2, per plugin (done for every plugin ported so far):**
  `bench/plugins/<name>/` with Corefile templates, fixtures and queries:
  `Corefile` plus optional `<case>.Corefile` cases (cache hits and misses,
  forward over UDP/TCP/DoT, zones of 100/10k/100k names, exact/suffix/regex
  rewrites, AXFR, TSIG-signed queries and UPDATEs, kubernetes and
  `k8s_external` against the fake API server, ...). Leading `# about:`,
  `# queries:`, `# dnsperf:` and `# needs:` comments describe each case
  (see `xtask/src/bench.rs`). DoQ, DoH3 and gRPC (`# dnsperf: -m doq`,
  `-m doh3`, `-m grpc`), which dnsperf can't speak, run `cargo xtask
  loadgen` instead: same arguments, same statistics output, plus latency
  percentiles. The result is the CPU time per query added
  over the `whoami` baseline, next to max QPS, latency at a fixed rate and
  peak RSS, with a warning when CoreDNS and KernDNS answer with different
  response codes. `cargo xtask bench --level 2 --plugin cache` runs a
  subset. A plugin isn't finished without a scenario: `cargo xtask bench
  --check` (in CI, no dnsperf needed) fails for any plugin in KernDNS's
  registry without a `bench/plugins/<name>/` directory or an entry in
  `bench/plugins/EXEMPT` (only plugins with no per-query work: `bind`,
  `root`, `debug`, `health`, `ready`, `reload`, `sign`), and checks that every case parses and
  uses its plugin. Still missing: forward failures. Follow-ups from the
  first full run (README), all fixed: the cache held a quarter of
  CoreDNS's entries in small caches (shard minimum 1 instead of 4) and
  locked every shard on each insert; AXFR sized every record with
  hickory's encoder and encoded each message twice (now 1.13M → 0.43M
  instructions per 100-name transfer); and a 100k-name `file` zone took
  248 MiB (now 66 MiB peak and steady, vs 117–177 MiB for CoreDNS)
  because of over-reserved per-name record lists and a load that held
  the whole file as tokens and records.
- **Level 3, common setups:** `bench/setups/<name>/`, same format: the
  caching resolver, kubeadm cluster DNS, a caching forwarder (hosts
  entries, a large cache with prefetch and `serve_stale`, forward over
  DoT), an authoritative server (two zones sharing a snippet, transfers,
  other zones refused), split
  horizon (`view`, queried from an internal and from an external client
  with dnsperf `-a`), a DoT and a DoH frontend (cache and forward behind
  the listener), and a mixed bridge chain vs all-Go CoreDNS (CoreDNS's
  etcd example: `etcd` in Go through the bridge, the rest in Rust, with
  and without the cache). `# bridge: etcd` makes the harness build the
  bridge and start KernDNS with `-bridge`; `# needs: etcd` starts a
  throwaway etcd with 500 SkyDNS services. `kubeadm` is kubeadm's
  default Corefile against the fake API server (1000 Services) with what
  pods send through the `ndots:5` search path (A and AAAA for each
  candidate), SRV, PTR, pod names and external names forwarded to the
  backend. `--kubeconfig PATH` points it at a live cluster instead, with
  `# live-queries:` for the objects in `bench/k8s/workloads.yaml`.
- **Kubernetes at scale:** kind + kwok with 1k/10k/50k Services and up to
  500k endpoints, a realistic in-cluster query mix including the `ndots:5`
  search-path NXDOMAINs, memory as the cluster grows, time to sync and become
  ready, change propagation, API server load, and behaviour when the API
  server restarts.

**CI:** `bench --check` and a one-second level 2 smoke run of a few
plugins on every PR (done). Planned: level 1 and a level 2 subset failing
on regressions above a threshold, with history tracked. Everything else nightly on a
dedicated machine, with a published report.

## Milestones

| | Scope | Exit criteria |
|---|---|---|
| **M0** (done) | Workspace, Corefile parser, core traits, hickory server, first plugins | `dig` works; compat overlay runs every upstream test against `kerndns` with every result classified |
| **M1** (done) | Wave 1 plugins, `reload`, `/metrics` | All relevant `test/` tests pass or are classified with a plugin reason; difftest in CI; bench harness with level 1/2 for wave 1 |
| **M2** (done) | `kubernetes` + `k8s_external` | Ported unit tables, `coredns/ci` kind tests and Go difftest all pass; scale benchmarks published, with memory at or below CoreDNS |
| **M3** (done) | Go bridge MVP | Go `etcd` inside a Rust chain; bridge micro-benchmarks; affinity groups enforced |
| **M4** (done) | Waves 3–4, DoT/DoH/DoQ/gRPC | Compat pass rate goes up; every plugin has a level 2 scenario (enforced by `bench --check` since the level 2 harness landed) |
| **M5** | Wave 5, optional out-of-process bridge, packaging | Nightly level 3 report; drop-in image replacing CoreDNS in kubeadm |

### M4 status

Done: waves 3 and 4, `erratic`, `multisocket`, and DoQ, DoH3 and gRPC
listeners with the `https`, `https3`, `quic` and `grpc_server` limits.
CoreDNS's integration tests went from 56 to 89 passing; the 4 still
failing need wave 5 plugins (`dnssec`, `siit`, `shed`) or ACME. Every
plugin has a level 2 benchmark scenario or a stated exemption, checked
by `cargo xtask bench --check` in CI.

Found while doing it: KernDNS refused to share a port that another
server still held, while CoreDNS sets `SO_REUSEPORT` on every listener
(now matched); `rewrite edns0` options are echoed the way CoreDNS's
in-place request mutation does it (and so is `revert`). Open from the
level 2 results: cache misses under constant eviction, AXFR CPU, and
peak memory of a 100k-name zone are behind CoreDNS (in progress).

### M5 status

Done: the drop-in image (`Dockerfile`, built in CI, not pushed yet):
`/coredns` entrypoint, uid 65532, `cap_net_bind_service` on the binary,
like CoreDNS's image. A copy of kubeadm's Deployment, Service, ConfigMap
and RBAC in a kind cluster with only the image changed: probes, metrics,
`reload` and `lameduck` work, and the answers match the cluster's
CoreDNS. The kubeadm level 3 setup runs against the fake API server or,
with `--kubeconfig`, a live cluster. The other level 3 setups are in
too: forwarder, authoritative, split horizon, DoT/DoH frontend and the
mixed bridge chain. Open: publishing the image, the
nightly level 3 report, and running the `coredns/ci` kind tests with the
image.

## Risks

- **Compat overlay blind spots:** some upstream tests check Go internals,
  CoreDNS's Go source or run CoreDNS's own `main`. Every skip is listed
  with a reason, so the pass rate can't be inflated quietly.
- **Kubernetes semantics:** many edge cases. Difftest against the Go plugin
  on the same cluster is the safety net.
- **Benchmark noise:** without a dedicated machine with pinned cores, Go vs
  Rust differences under 5–10% won't mean anything.
- **The fake caddy setup in the Go bridge** and **per-query bridge cost**.
  The bridge column in the benchmarks measures the second one directly.
