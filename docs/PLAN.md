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
  tag `etcd`) against KernDNS with the Go `etcd` plugin (now that `etcd`
  has a Rust port, through `-bridge.prefer etcd`, also settable as
  `$KERNDNS_BRIDGE_PREFER`), against a
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
- Third-party plugins outside plugin.cfg work too: the bridge exports
  CoreDNS's directive order (`kb_directives`), and KernDNS places each
  unknown directive after its predecessor there (`order::add_directives`).
- Not yet: Go metadata flowing back to Rust; a Go plugin's `upstream`
  lookups resolving through the Rust server (out-of-zone CNAME, SRV and MX
  targets lose their addresses, the 188 differences of `etcd-difftest
  --bridge`); and the out-of-process mode (M5).

**Choosing per directive:** Rust port if one exists, else the bridge if it
provides the plugin, else an error saying how to build the bridge with it.
`-bridge.prefer PLUGINS` (or `$KERNDNS_BRIDGE_PREFER`) runs those plugins
in Go even though a Rust port exists, for A/B tests and benchmarks (the
`bridge` setups and `bench/plugins/etcd/bridge` use it for `etcd`).

## Encrypted listeners (M4)

Every transport CoreDNS serves has a KernDNS listener, all on the same
dispatch path (one parse, one encode per response) and all kept across
reloads like the plain DNS ones:

| Scheme | Listener | Crates | Limits plugin |
|---|---|---|---|
| `tls://` | DoT | tokio-rustls | `timeouts` |
| `https://` | DoH, HTTP/1.1 and HTTP/2 | hyper | `https` (`max_connections` 200, `max_streams` 250), `timeouts` |
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

Through the Go bridge until someone needs a port: `route53`,
`clouddns`, `azure`, third-party plugins.

`etcd` is ported (`crates/plugins/src/etcd`). Like CoreDNS it reads etcd
on every query (a prefix range, an exact read when the prefix is empty,
and a `LeaseTimeToLive` per key with a lease) and leaves caching to
`cache`; records go through the shared service backend
(`crate::backend`, CoreDNS's `backend_lookup.go`), so wildcards (`*`,
`any`), groups, SRV weights per priority, `targetstrip`, CNAME chasing
in and out of the zone (out of zone through the server, like
`upstream`), the time-based SOA serial, lease TTL bounds and
`no_apex_fallback` behave as in CoreDNS. CoreDNS's etcd plugin has no
metrics of its own. The table tests of `plugin/etcd` and `plugin/etcd/msg`
run against an in-memory key space; `cargo xtask etcd-difftest` serves
the benchmark's 500 services plus the unit tests' records, leases, long
TXT strings, weights, out-of-zone targets and broken JSON from one
throwaway etcd to CoreDNS and KernDNS (two Corefile variants, 16k
queries each) with no differences. With `--bridge` (Go `etcd` inside
KernDNS) it finds the bridge's one gap: Go's `upstream` can't resolve
through the Rust server, so out-of-zone CNAME and SRV/MX targets lose
their addresses. Differences from CoreDNS:

- The etcd v3 client is KernDNS's own (KV.Range, Lease.LeaseTimeToLive,
  Auth.Authenticate over gRPC on hyper's HTTP/2 client, protobuf by hand)
  rather than the `etcd-client` crate, which needs `protoc` at build time
  (not in CI, the image build or a plain Rust toolchain) and tonic/prost.
  It spreads calls round robin over the endpoints and skips unreachable
  ones, connects lazily, and fetches the auth token on first use (and
  again when etcd calls it invalid or stale); unlike `clientv3` it sends
  no keepalive pings and does not back off and retry within the 5 s
  budget beyond trying each endpoint once. Lease lookups get the same
  5 s timeout (CoreDNS uses none).
- Service JSON matches field names case-insensitively in ASCII only
  (Go also folds `K`/`ſ`), and invalid UTF-8 is an error (Go replaces
  it); integers beyond 32 bits keep their low bits earlier than in Go.
- Error messages in logs differ in wording.

Porting it fixed three bugs in the shared backend (none affected
`kubernetes`): SRV address records for IP services ignored `targetstrip`,
MX deduplicated on the wrong name, and TXT strings of exactly 255·n
bytes lacked CoreDNS's trailing empty string.

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

### Parity with CoreDNS 1.15.0: the other plugins

Every ported plugin except `forward`, `cache`, `kubernetes`,
`k8s_external` (see its own table) and `etcd` (see above), compared
option by option (README, `setup.go`) and in its handler with CoreDNS
1.15.0. Plugins not listed have no known gap: `acl`, `any`, `auto`,
`autopath`, `bufsize`, `dns64`, `dnstap`, `file`, `geoip`, `grpc_server`,
`header`, `hosts`, `https`, `https3`, `local`, `metadata`, `minimal`,
`nsid`, `on`, `quic`, `ready`, `rewrite`, `root`, `secondary`, `shed`,
`sign`, `siit`, `trace`, `transfer`, `whoami`. Deliberate differences
described elsewhere in this plan (`pprof`'s Go profiles, `trace`'s B3
headers, `on`'s hooks on reload, `shed` needing a restart, the `version`
strings) are not repeated.

| Plugin | Gap | Status |
|---|---|---|
| Corefile | caddy's lexer: a `"` only quotes at the start of a token, `#` starts a comment anywhere outside quotes, no backtick quotes (KernDNS stripped quotes inside tokens: `group("a")` became `group(a)`) | done |
| `bind` | interface names (`bind lo`), IPv6 link-local addresses of an interface with the interface as zone (the listener's scope id) | done |
| `bind` | `except` applies to its own `bind` directive only; CoreDNS's error messages; startup banner `.:53 on 127.0.0.1` | done |
| `bind` | when `except` removes every address CoreDNS starts the block without a listener; KernDNS refuses the Corefile | not done: such a block is a mistake, and an error says so |
| `errors` | `consolidate DURATION REGEXP [LEVEL] [show_first]`, pending summaries printed on reload; `invalid log file` and `Unknown field` errors | done (KernDNS also prints pending summaries on SIGTERM, which CoreDNS drops) |
| `errors` | `stacktrace` prints a stack trace with recovered panics | not done: accepted, KernDNS logs the panic without a trace |
| `template` | `var NAME EXPRESSION` (`.Var`) and `expr EXPRESSION` with expr-lang's typing (`'x' + 1` is a setup error), `group()`, reserved names; evaluation errors are SERVFAIL | done, with KernDNS's expr evaluator (`crates/plugins/src/expr.rs`), which covers the README's expressions and most of the language: literals, operators with expr-lang's precedences, `?:`, `??`, indexing, the string, number and list builtins and the predicates `all`/`any`/`none`/`one`/`filter`/`map`/`count` with `#`. Not covered (setup error): maps, member access, slices, ranges, pipes, `let`, `if`, date/JSON/base64 builtins |
| `template` | template execution errors were logged with a `plugin/template:` prefix | done (logged as CoreDNS does) |
| `template` | Go `text/template` features beyond the supported subset (`{{ $x := ... }}`, `range`, `with`, `define`, other `.Message` fields) | not done: setup error, see `template/gotmpl.rs` |
| `view` | expressions: the same evaluator as `template`, so `view` gains `?:`, `??`, predicates and builtins | done |
| `tls` | `keylog FILE` (NSS key log format, mode 0600, appended) | done |
| `tls` | `client_auth request` and `require` accept a client certificate without verifying it (Go's `RequestClientCert`, `RequireAnyClientCert`); KernDNS verified it against the CA | done |
| `dnssec`, `sign` | RSASHA1 (algorithms 5, 7) and RSA keys under 2048 bits | not done: ring can't sign them; RFC 8624 forbids signing with RSASHA1. KernDNS refuses such keys at startup |
| `dnssec` | `key aws_secretsmanager` | not done: it needs the AWS SDK (a large dependency tree for one option). Run `dnssec` in Go with `-bridge.prefer dnssec` instead |
| `health` | `lameduck` also slept on every reload; CoreDNS only on the final shutdown | done (`Controller::on_final_shutdown`) |
| `health` | the self-probe every second, `coredns_health_request_duration_seconds` and `coredns_health_request_failures_total` | done |
| `health`, `ready`, `prometheus`, `pprof` | `SO_REUSEPORT` on the HTTP listener, so several blocks can share an address | done |
| `reload` | `Running configuration SHA512` hashes Go's `json.Marshal` of caddy's server blocks: the same hash as CoreDNS for the same Corefile | done |
| `reload` | `coredns_reload_failed_total`, `coredns_reload_version_info{hash,value}`; a Corefile that failed to load isn't retried until it changes again | done |
| `reload`, SIGUSR1, `-control` | a reload whose new configuration fails to start (a startup hook errors, a listener can't bind) kept the new configuration; caddy's `Instance.Restart` rolls back: the running configuration's `OnRestart` hooks, the new one's `OnStartup` hooks and binds, then on failure the old one's `OnRestartFailed` hooks, `[ERROR] Restart failed: starting with listener file descriptors: ...` (then `[ERROR] SIGUSR1: ...` or `plugin/reload`'s message and `coredns_reload_failed_total`); on success the old one's `OnShutdown` hooks | done (`Controller::on_restart`/`on_restart_failed`; `health`, `ready`, `prometheus` and `dnstap`'s listener stop on restart and start again when it fails). The old listeners answer throughout. Unlike caddy, the discarded configuration's shutdown hooks run, and its readiness checks and `reload` interval are replaced by the old ones; `dnstap`'s outgoing connection is closed by the old configuration's shutdown, not on restart, so it isn't lost on a failed reload. Go plugins in the bridge get no restart hooks |
| `log` | `{>opcode}` is the number, as in CoreDNS (KernDNS printed `QUERY`); `class` filters classify with `response.Typify`/`Classify` (NOERROR without SOA is success, NXDOMAIN with answers an error, ...); `log/type` and `log/class` metadata; `unknown property` error | done |
| `log` | `{duration}` counts from the start of the request, not from when `log` runs; `{rsize}` is `-` instead of `0` when nothing was written | not done: sub-millisecond differences, and `-` is what `{rcode}` shows in the same case |
| `chaos` | a VERSION over 255 bytes given together with authors panicked on `version.bind`; now there is no answer, as in CoreDNS (the message can't be packed) | done |
| `chaos` | default authors are KernDNS's, not CoreDNS's OWNERS | not done, deliberate |
| `timeouts` | `read`, `write` and `idle` apply to DoH (`https://`) listeners as on CoreDNS's `http.Server` (defaults 3 s/5 s/10 s): TLS handshake within the shorter of read and write; HTTP/1 requests within read, answers within write after the headers (else the connection closes), kept-alive connections closed after idle; HTTP/2 bodies within read, answers within write (else `RST_STREAM` `INTERNAL_ERROR`), connections without streams closed after idle. A late body is a 400. DoH3 uses only idle, DoQ read and idle, as in CoreDNS | done |
| `prometheus` | the `plugin` label of `coredns_dns_responses_total` (the plugin that wrote the response) was always empty | done, as CoreDNS fills it: the plugin right after `prometheus` in the chain whenever a response was written below it (CoreDNS's `pluginWriter` only tags the metrics recorder it wraps directly, so `prometheus; errors; forward` counts `errors`), empty when the server writes the error response |
| `prometheus` | `tls` block option (a Prometheus web config file for HTTPS) | not done yet: setup error |
| `debug` | hex dumps of mismatched upstream replies (`forward`, `grpc`) | not done: only the dump, the FORMERR answer is the same |
| `cancel` | stops the rest of the chain at the timeout instead of cancelling a context plugins watch | not done: same SERVFAIL for the client |
| `tsig` | a secret that isn't base64 fails at startup; CoreDNS fails each request it signs | not done: the startup error is clearer |
| `multisocket` | `quic://` and `https3://` always use one socket | not done: QUIC listeners share one socket by design |
| `proxyproto` | `quic://` and `https3://` (see above) | not done yet |
| `dynupdate` | the ZONE argument isn't normalized like `plugin.Host` (reverse CIDRs, `dns://`, ports) | not done: zones are given as names in practice |
| `loadbalance` | `prefer` inside a `weighted` block is accepted; CoreDNS rejects it | not done: harmless |
| `grpc` | an upstream with a scheme other than `dns://`/`unix://` is a setup error (see above) | not done, deliberate |
| `erratic` | readiness is per plugin name, not per server block | not done: only visible with `erratic` in several blocks |

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
  `apiserver_qps/burst/max_inflight`, `startup_timeout`, `multicluster`
  and `zonal`.
- Records: A, AAAA, SRV, PTR, ExternalName CNAME, headless,
  `dns-version`, and correct NXDOMAIN vs NODATA.
- `ready` reports not-ready until all watchers have synced. Implements
  `Transferer` for AXFR. Exposes the same `coredns_kubernetes_*` metrics.
- Tests: ported table tests from `plugin/kubernetes/*_test.go`, the
  `coredns/ci` kind tests, and difftests against the Go plugin on the same
  cluster.

### M2 status

- CoreDNS's own kubernetes and k8s_external tests are extracted from the Go
  tests (`cargo xtask k8s-cases`, `go/k8sdump`) and replay against the Rust
  port with identical results: 130 handler cases (serve, namespaces,
  not-synced, pod modes, empty services, apex, case preservation,
  multicluster, zonal), the zone transfers of `xfr_test.go` (record for
  record, in order), `metadata_test.go`, and k8s_external's 38 handler
  cases and its transfers (`crates/kubernetes/tests/upstream_*.rs`).
- `cargo xtask k8s-difftest` against a live kind cluster: 57,344 queries over
  four Corefile variants (kubeadm-like, `pods verified` +
  `endpoint_pod_names`, `namespaces` + `ignore empty_service`,
  `k8s_external` with `headless`): no differences.
- coredns/ci's end-to-end tests (`test/kubernetes`) run in the CI job
  `kind` against the KernDNS image; see go/compat/expectations-kind.txt.
- `cargo xtask fake-api` serves the benchmarks' fake API server on its own,
  to run CoreDNS and kerndns side by side (AXFRs, metadata in logs and the
  `coredns_kubernetes_*` metrics match).
- `cargo xtask k8s-bench`: faster sync and less memory than CoreDNS at 1k,
  10k and 50k services (see README). Resident memory after a large sync is
  higher than the live index needs because the allocator keeps freed list
  pages; a different allocator or smaller pages would trade that against
  sync time.

#### Parity with CoreDNS 1.15.0 (`plugin/kubernetes`, `plugin/k8s_external`)

| Option / behaviour | CoreDNS | KernDNS |
|---|---|---|
| `kubernetes [ZONES...]`, once per block, a non-reverse zone required | `setup.go` | same, same errors |
| `endpoint URL` (several: deprecated, first used) | client-go | same (warning for several) |
| `tls CERT KEY CACERT` (only with `endpoint`) | client-go | same |
| `kubeconfig KUBECONFIG [CONTEXT]` | `clientcmd` | same (kube-rs kubeconfig loader) |
| in-cluster service account | `rest.InClusterConfig` | same (`kube::Config::incluster`) |
| `apiserver_qps`, `apiserver_burst`, `apiserver_max_inflight` | client-go rate limiter (default 5 QPS, burst 10) and an in-flight round tripper | same: a tower layer with a token bucket (same defaults) for every request but watches, like client-go, and an in-flight limit held until the response headers; same validation errors |
| `namespaces`, `namespace_labels` (not both) | `namespace.go` | same |
| `labels EXPRESSION` | parsed at setup (`ParseToLabelSelector`) | **passed to the API server as is**: an invalid selector is rejected by the API server (a logged watch error) instead of at setup |
| `pods disabled\|insecure\|verified` | `findPods` | same; the pod watch uses CoreDNS's field selector (no Succeeded/Failed/Unknown pods) and keeps terminating pods until they are deleted |
| `endpoint_pod_names` | `endpointHostname` | same (pod names of 64+ characters ignored) |
| `ttl` (0..3600), `noendpoints`, `fallthrough [ZONES]`, `ignore empty_service`, `startup_timeout` | `setup.go` | same, same errors |
| `multicluster [ZONES]` (MCS API: ServiceImports, EndpointSlices with `multicluster.kubernetes.io/service-name`) | `findMultiClusterServices`, own serial | same, incl. `endpoint.cluster.service...` names, the ServiceImport watch selected by `namespace_labels` (as CoreDNS does) and multicluster AXFR |
| `zonal` (`topozone.pin\|prefer._zone.service.ns.svc.zone`), not with `noendpoints` | `parse.go`, `findServices` | same (NODATA for an empty zone, `prefer` falls back) |
| EndpointSlices | ready condition only (nil = ready), all address types | same |
| A, AAAA, SRV (named and unnamed ports), PTR (services, endpoints), ExternalName CNAME (+ upstream), headless + hostnames, `dns-version` TXT, NXDOMAIN vs NODATA, case preservation | handler, `plugin.A/SRV/...` | same (replayed cases) |
| wildcard (`*`) queries | removed in CoreDNS 1.9: no special meaning | same |
| SOA serials | `Modified` internal / external / multicluster, CoreDNS's change detection | same |
| NS and glue: the DNS service found through the server's own addresses (`boundIPs`, `nsAddrs`), else `ns.dns.<zone>` | `ns.go`, `local.go` | same |
| not synced: SERVFAIL for names in the zones; `ready` until synced; start waits up to `startup_timeout` | `handler.go`, `ready.go` | same |
| lost API connection | informers retry, `HasSynced` stays true | same (kube-rs watchers retry with backoff, the index keeps serving) |
| zone transfers (`transfer`) incl. pods' endpoint names, IXFR serial check | `xfr.go` | same (`xfr.rs`) |
| `kubernetes/*` metadata (`client-namespace`, `client-pod-name`, `client-label/*`, `endpoint`, `kind`, `namespace`, `port-name`, `protocol`, `service`, `zone`, `parse-error`) | `metadata.go` | same. Like CoreDNS in a server, `kubernetes/cluster` is never set: the multicluster check uses the request's zone, which the server leaves empty when it collects metadata |
| `coredns_kubernetes_dns_programming_duration_seconds{service_kind}` | `object/metrics.go` | same (from `endpoints.kubernetes.io/last-change-trigger-time`; like CoreDNS, no `headless_without_selector`) |
| `coredns_kubernetes_rest_client_{request_duration_seconds,rate_limiter_duration_seconds,requests_total}` | client-go metrics hooks | same names, labels and buckets. CoreDNS's informers use streaming lists (WatchList), so its lists are watches and only counted; KernDNS lists with paged GETs, which are also timed |
| `autopath @kubernetes` | `autopath.go` | same |
| `k8s_external`: `apex`, `ttl`, `headless`, `fallthrough`, several zones, PTR of external IPs, AXFR (`Transferer`), own serial | `plugin/k8s_external` | same (replayed cases and transfers) |
| API client details: protobuf content type, CoreDNS user agent, klog adapter | client-go | not ported: JSON, kube-rs's user agent and KernDNS's own logging; not visible in DNS |

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
2. **`coredns/ci` end-to-end tests** (`cargo xtask kind-test`, done): the CI
   job `kind` runs coredns/ci's `test/kubernetes` on every PR with the
   KernDNS image as a kind cluster's DNS, each test in its own process,
   compared with `go/compat/expectations-kind.txt`. A second run with
   CoreDNS's own image is the control: it separates failures of the
   harness or the runner from KernDNS's.
   **Kubernetes' conformance DNS tests** (`cargo xtask k8s-conformance`,
   done): the CI job `k8s-conformance` swaps the KernDNS image into the
   kube-system/coredns Deployment of a kind cluster (`kubectl set image`,
   kubeadm's Corefile unchanged) and runs Kubernetes' own e2e specs from
   the release's prebuilt `e2e.test` and `ginkgo`
   (kubernetes-test-linux-amd64.tar.gz, checksum-pinned; kind v0.33.0 and
   `kindest/node:v1.37.0` pinned by digest to the same version): every
   `[sig-network] DNS` spec of test/e2e/network/dns*.go (the 8
   `[Conformance]` ones, partial names, search path limits, hostNetwork,
   configurable resolv.conf, and the `[Serial]` ConfigMap tests that
   change the Corefile to stubDomain/upstream forwarding and back),
   `Networking ... using DNS`, the `[sig-network] Services` conformance
   specs (Services reached by name, ExternalName) and `should create
   endpoints for unready pods`. Skipped: `[Provider:gce]` and the
   `[Feature:PerformanceDNS]` capacity test. ginkgo runs 4 parallel
   processes (`[Serial]` specs last, alone) and writes a JSON report, which
   is compared with `go/compat/expectations-conformance.txt`; a second run
   with CoreDNS 1.15.0's image is the control. The specs take under two
   minutes; the whole job, with the image build and the cluster, 6 to 8.
   Result: all 37 pass, for CoreDNS too. Hydrophone or sonobuoy would run
   the same `e2e.test` inside the cluster from the conformance image; the
   binary on the runner is simpler and its report needs no copying out.
3. **Plugin unit tests** (`cargo xtask plugin-cases`, done): the tables of
   each plugin's `*_test.go` are extracted from the Go source into JSON
   fixtures and replayed against KernDNS through a Corefile
   (`crates/server/tests/plugin_cases`), with `test.SortAndCheck`'s
   semantics. Every table runs or is listed with a reason, and every row
   passes or is an expected failure with a reason; per-plugin coverage is
   in [plugin-cases.md](plugin-cases.md).
4. **Differential testing** (`cargo xtask difftest`): same Corefile and
   fixtures against CoreDNS and KernDNS, a query corpus including fuzzed
   queries, diffs normalised for TTL and RRset order. A plugin becomes the
   default Rust implementation only after it passes.
5. **Fuzzing** (`fuzz/`, cargo-fuzz, done): the Corefile parser, dispenser
   and every plugin's setup; the wire request path with a representative
   chain; the Rust side of the bridge's message handling (callbacks from Go,
   the plugin list, directive rendering). CI runs each target for 60 s.
6. **Dependency checks** (done): cargo-deny ([`deny.toml`](../deny.toml):
   RustSec advisories, licenses, duplicates as warnings, crates.io only)
   for the workspace and `fuzz/`, and govulncheck for `go/bridge` (with every
   in-tree CoreDNS plugin, tag `allplugins`) and `go/difftest`, in the
   `Dependencies` workflow on PRs, pushes to main and weekly. A finding is
   fixed by bumping the dependency (Go: in the bridge's go.mod, never
   CoreDNS itself) or ignored in `deny.toml` with the advisory ID and reason.

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
  the listener), CoreDNS's etcd example with and without the cache, all
  in Rust (`etcd`) and as a mixed bridge chain vs all-Go CoreDNS
  (`bridge`: `etcd` in Go through the bridge, the rest in Rust).
  `# bridge: etcd` makes the harness build the bridge and start KernDNS
  with `-bridge` and `-bridge.prefer etcd`; `# needs: etcd` starts a
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

Done:

- **Wave 5:** `dnssec`, `sign`, `dnstap`, `grpc`, `siit`, `shed`,
  `proxyproto`, `on`, `pprof`, `geoip`, `trace`, ACME certificates in
  `tls`, and `etcd` in Rust. Every plugin in CoreDNS's `plugin.cfg` is
  ported except the cloud backends `route53`, `clouddns`, `azure` and
  `nomad`, which run through the bridge.
- **Drop-in image:** `Dockerfile` (base images pinned by digest, updated by
  Dependabot) with the `/coredns` entrypoint, uid 65532 and
  `cap_net_bind_service` on the binary, like CoreDNS's image. CI builds it
  on every PR and pushes `ghcr.io/mrueg/kerndns` on pushes to `main`
  (`main`, `latest`, `sha-<commit>`) and on `v*` tags. A copy of kubeadm's
  Deployment, Service, ConfigMap and RBAC with only the image changed:
  probes, metrics, `reload` and `lameduck` work, and the answers match the
  cluster's CoreDNS.
- **`coredns/ci` kind tests** in CI with the image: all 13 that exercise
  the cluster DNS pass (the same as CoreDNS's own image); see Testing.
- **Kubernetes' own DNS conformance tests** in CI with the image in
  kind's kube-system/coredns Deployment (kubeadm's Corefile): all 37
  `[sig-network] DNS` and `Services` conformance specs of Kubernetes
  v1.37.0 pass, the same as CoreDNS's own image; see Testing.
- **Kubernetes parity** with CoreDNS 1.15.0 (see its parity table).
- **`forward` parity:** DoH (`https://`, `doh_method`) and DoQ (`quic://`)
  upstreams, upstreams given as host names (resolved at startup with
  `resolver` or the system resolver), `max_idle_conns`.
- **Level 3 setups:** resolver, kubeadm, forwarder, authoritative, split
  horizon, DoT/DoH frontend, etcd and the mixed bridge chain.
- **Testing:** CoreDNS's integration tests at 109 pass / 1 expected
  failure / 12 skipped, with in-place reload through `kerndns -control`;
  CoreDNS's plugin table tests replayed (`cargo xtask plugin-cases`);
  fuzzing in CI.

Open:

- The nightly level 3 report, and the CI regression gate (see
  Benchmarks), which need a dedicated machine.
- The optional out-of-process bridge, and the bridge gaps listed under M3.
- Features the plugin table tests show as missing:
  RSASHA1 keys in `dnssec` (which ring can't sign; see the parity table
  of the other plugins).
- The gaps marked "not done yet" in the parity table of the other
  plugins: `prometheus`'s `tls` option, PROXY protocol on QUIC
  listeners.

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
