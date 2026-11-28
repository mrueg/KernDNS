# CoreDNS plugin table tests against KernDNS

Most CoreDNS plugin tests are tables: a slice of structs (or `test.Case`s)
run in a loop against a plugin. KernDNS runs those tables against its own
plugins, from the upstream source, so a CoreDNS version bump regenerates
them.

## How it works

1. **Extraction** (`cargo xtask plugin-cases`, [`go/plugincases`](../go/plugincases)).
   For each plugin the generator parses the package's `*_test.go` files and
   finds every table: a slice, array or map literal or a `test.Case`,
   assigned to a package-level variable or to a local variable in a `Test*`
   function. It copies the table's source, with the local type, constant
   and variable declarations it depends on, into a function in a generated
   test file, adds that file to the package with `go test -overlay` and runs
   it, so every identifier means what it means in the original test. The
   values are written to `crates/server/testdata/plugin_cases/<plugin>.json`
   with DNS records in presentation format, together with the package's
   string constants and variables (zone files, hosts files, keys) and the
   string literals of each test function (`Func/name`). Tables that don't
   compile outside their function (they use a variable computed at run
   time) are listed in the fixture with the compiler's message. Nothing in
   the CoreDNS checkout is modified.
2. **Replay** (`crates/server/tests/plugin_cases`, part of `cargo test`).
   A driver per test function sets up the plugin from a Corefile through
   KernDNS's normal setup (`config::load`, startup hooks) and sends each
   row's query through the server's dispatcher (routing, plugin chain,
   error responses, EDNS echo; no sockets, TCP so nothing is truncated,
   remote address `10.240.0.1` like `test.ResponseWriter`). The Go tests'
   next handlers (`test.NextHandler`, `test.ErrorHandler`, hand-written
   ones) are a test-only plugin registered as `nomad`, the last directive
   in `plugin.cfg`. The dispatcher reports what the chain did, so a check on
   `rec.Msg` sees only what a plugin wrote, not the server's error response.
3. **Comparison.** `test.SortAndCheck` semantics: the rcode, the number of
   records per section, and for each record the owner name, TTL (303 means
   any), type and the fields `test.Section` compares (A/AAAA address,
   SRV/MX/NS/CNAME/PTR/SOA targets, TXT, HINFO, RRSIG covered type, labels
   and signer, NSEC next name, SVCB/HTTPS data). Go sorts the response by
   its text form and compares position by position against the table,
   which lists records in that order; the harness matches records
   irrespective of order instead, so Go's text formatting doesn't matter.
   An OPT record only counts if the table expects one (the server echoes
   the client's). Other tables are checked the way their Go test checks
   them (rcode, a flag, the NSID option, the extended error, ...).
4. **Setup tables** (`{input, shouldErr, expectedErrContent}` and the like)
   run for every plugin: setup must fail exactly when it fails in CoreDNS,
   with the expected message when the table has one. The parsed values the
   Go test then compares are Go internals and not checked.

Every table is either run or listed in
[`expectations.txt`](../crates/server/testdata/plugin_cases/expectations.txt)
as `skip` with the reason, and every row passes or is listed as `xfail`
with the reason (a passing xfail fails the test). Rows that can't apply
to a server (for example a fixed clock in the Go test) are `skip` rows.

```sh
cargo xtask plugin-cases                      # regenerate every fixture (compiles each package's tests: slow)
cargo xtask plugin-cases --plugins file,hosts # some of them
cargo test -p kerndns-server --test plugin_cases -- --nocapture  # per-plugin totals
```

## Coverage

Rows are table rows (nested tables count their inner rows). *Skipped*
counts the rows of skipped tables and skipped rows; *tables not
extractable* are listed in the fixture with the reason. Totals from
`cargo test -p kerndns-server --test plugin_cases -- --nocapture`.

| Plugin | Rows extracted | Pass | Expected failures | Skipped | Tables not extractable | Files run | Files with no table run |
|---|---:|---:|---:|---:|---:|---|---|
| `acl` | 67 | 64 | 0 | 3 | 0 | `acl_test.go`, `setup_test.go` | - |
| `any` | 5 | 5 | 0 | 0 | 0 | `any_test.go` | - |
| `auto` | 44 | 19 | 0 | 25 | 0 | `setup_test.go` | `auto_test.go`, `regexp_test.go`, `walk_test.go`, `xfr_test.go`, `zone_test.go` |
| `autopath` | 7 | 3 | 0 | 4 | 1 | `autopath_test.go` | `setup_test.go` |
| `bufsize` | 6 | 6 | 0 | 0 | 0 | `setup_test.go` | - |
| `cache` | 177 | 116 | 0 | 61 | 1 | `cache_test.go`, `setup_test.go` | `dnssec_test.go`, `prefetch_test.go`, `qclass_test.go`, `serve_stale_recheck_test.go` |
| `chaos` | 6 | 6 | 0 | 0 | 0 | `chaos_test.go`, `setup_test.go` | - |
| `debug` | 2 | 2 | 0 | 0 | 0 | `debug_test.go` | - |
| `dns64` | 31 | 31 | 0 | 0 | 0 | `dns64_test.go`, `setup_test.go` | - |
| `dnssec` | 28 | 24 | 4 | 0 | 0 | `handler_test.go`, `setup_test.go` | - |
| `dnstap` | 4 | 0 | 0 | 4 | 1 | - | `io_test.go`, `listener_test.go`, `setup_test.go` |
| `dynupdate` | 42 | 0 | 0 | 42 | 0 | - | `dynupdate_test.go`, `store_test.go` |
| `erratic` | 18 | 18 | 0 | 0 | 0 | `erratic_test.go`, `setup_test.go` | - |
| `errors` | 44 | 26 | 0 | 18 | 0 | `setup_test.go` | `errors_test.go` |
| `file` | 153 | 115 | 0 | 38 | 4 | `alias_delegation_test.go`, `delegation_test.go`, `dnssec_test.go`, `ds_test.go`, `ent_test.go`, `escape_test.go`, `file_test.go`, `glue_test.go`, `lookup_test.go`, `svcb_test.go`, `wildcard_test.go` | `closest_test.go`, `reload_test.go`, `setup_test.go`, `zone_test.go` |
| `forward` | 201 | 87 | 6 | 108 | 0 | `resolve_test.go`, `setup_policy_test.go`, `setup_test.go` | `forward_test.go` |
| `geoip` | 27 | 8 | 0 | 19 | 0 | `setup_test.go` | `geoip_test.go` |
| `grpc` | 32 | 23 | 0 | 9 | 1 | `setup_policy_test.go`, `setup_test.go` | `grpc_test.go`, `policy_test.go`, `proxy_test.go` |
| `grpc_server` | 13 | 13 | 0 | 0 | 0 | `setup_test.go` | - |
| `header` | 16 | 16 | 0 | 0 | 0 | `header_test.go`, `setup_test.go` | - |
| `health` | 8 | 8 | 0 | 0 | 0 | `setup_test.go` | - |
| `hosts` | 72 | 68 | 0 | 4 | 0 | `hosts_test.go`, `hostsfile_test.go`, `setup_test.go`, `wildcard_test.go` | - |
| `https` | 0 | 0 | 0 | 0 | 1 | - | `setup_test.go` |
| `https3` | 10 | 10 | 0 | 0 | 0 | `setup_test.go` | - |
| `loadbalance` | 70 | 12 | 0 | 58 | 0 | `setup_test.go` | `loadbalance_test.go`, `prefer_test.go`, `weighted_test.go` |
| `local` | 13 | 13 | 0 | 0 | 0 | `local_test.go` | - |
| `log` | 45 | 21 | 0 | 24 | 0 | `setup_test.go` | `json_test.go`, `log_test.go` |
| `loop` | 3 | 0 | 0 | 3 | 0 | - | `setup_test.go` |
| `metadata` | 22 | 10 | 0 | 12 | 0 | `setup_test.go` | `metadata_test.go` |
| `metrics` | 26 | 8 | 0 | 18 | 0 | `setup_test.go` | `metrics_test.go`, `recorder_test.go` |
| `minimal` | 16 | 3 | 0 | 13 | 0 | `minimal_test.go` | - |
| `multisocket` | 10 | 10 | 0 | 0 | 0 | `multisocket_test.go` | - |
| `nsid` | 2 | 2 | 0 | 0 | 1 | `nsid_test.go` | `setup_test.go` |
| `pprof` | 16 | 13 | 0 | 3 | 0 | `setup_test.go` | `pprof_test.go` |
| `proxyproto` | 24 | 22 | 0 | 2 | 0 | `setup_test.go` | `metadata_test.go` |
| `quic` | 27 | 27 | 0 | 0 | 0 | `setup_test.go` | - |
| `ready` | 10 | 10 | 0 | 0 | 0 | `setup_test.go` | - |
| `rewrite` | 363 | 249 | 0 | 114 | 0 | `name_test.go`, `rcode_test.go`, `rewrite_test.go`, `setup_test.go`, `ttl_test.go` | `cname_target_test.go`, `edns0_test.go`, `reverter_test.go` |
| `root` | 0 | 0 | 0 | 0 | 1 | - | `root_test.go` |
| `secondary` | 13 | 11 | 0 | 2 | 0 | `setup_test.go` | `catalog_test.go` |
| `shed` | 4 | 4 | 0 | 0 | 0 | `setup_test.go` | - |
| `sign` | 6 | 1 | 0 | 5 | 0 | `setup_test.go` | `nsec_test.go` |
| `siit` | 43 | 28 | 0 | 15 | 0 | `setup_test.go`, `siit_test.go` | `siit_dns64_test.go` |
| `template` | 108 | 83 | 0 | 25 | 0 | `expr_test.go`, `setup_test.go`, `var_test.go` | `template_test.go` |
| `timeouts` | 0 | 0 | 0 | 0 | 1 | - | `timeouts_test.go` |
| `tls` | 27 | 14 | 0 | 13 | 0 | `acme_test.go`, `tls_test.go` | - |
| `trace` | 41 | 30 | 0 | 11 | 0 | `setup_test.go` | `trace_test.go` |
| `transfer` | 7 | 7 | 0 | 0 | 0 | `setup_test.go` | - |
| `tsig` | 38 | 0 | 0 | 38 | 1 | - | `setup_test.go`, `tsig_test.go` |
| `view` | 11 | 7 | 0 | 4 | 0 | `setup_test.go` | `view_test.go` |
| `whoami` | 4 | 4 | 0 | 0 | 0 | `whoami_test.go` | - |
| **total** | **1962** | **1257** | **10** | **695** | **13** | | |

`etcd` and `kubernetes` are covered elsewhere (the etcd port, and
`cargo xtask k8s-cases`). `bind`, `cancel` and `reload` have no table
tests. Not ported to KernDNS, so not extracted: `azure`, `clouddns`,
`route53`, `nomad`, `k8s_external` (its tables need the kubernetes
fakes; see the kubernetes crate), `deprecated`, `import`.

## Not covered, by kind

- **Go helpers.** Tables that call an unexported function directly
  (`replaceWithAsteriskLabel`, `computeTTL`, `splitZone`, ...) test Go
  code, not behaviour a server shows.
- **Mocked clocks and Go internals.** The cache's stale and prefetch
  tests move the cache's clock, which only a unit test can reach; they
  are ported as Rust unit tests with the cache's test clock
  (`crates/plugins/src/cache/tests.rs`) and skipped here. Tests
  that read Go metrics registries, mock tracers, Go loggers or parsed
  structs are skipped.
- **Values computed at run time.** Tables that use a temp file name, a
  test server's address or another local value can't be evaluated outside
  the test; the fixture lists them with the compiler's message.
- **Features KernDNS doesn't have yet** are `xfail` rows, each with the
  missing feature: `forward` `resolver` and
  `https://`/`quic://` upstreams, RSASHA1 signing keys.
- **Files from the Go package directory.** Setup rows that read
  `testdata/...` or files the Go test writes into its working directory
  (resolv.conf, certificates, MaxMind databases) are skipped rows; files
  the test writes from string constants (dnssec keys, zones, hosts files)
  are written to a temporary directory instead.

## What the tables found

- `transfer` rejected IPv6 zone identifiers (`to [fe80::1%eth0]:53`),
  which CoreDNS accepts and keeps. Fixed.
- `prometheus` rejected CoreDNS 1.15's `runtime_metrics` option. It is
  accepted now, with a warning (there is no Go runtime to report on).
- `template`'s `var a group("a")` lost its quotes: KernDNS's Corefile
  lexer treated a `"` inside a token as a quote, where caddy's only
  quotes at the start of a token (and starts a comment at any `#`).
  Fixed in the lexer.

Every other difference is a missing feature (above) or a property of the
Go unit test rather than of the plugin (a fixed clock, no running server
for upstream lookups, a nil remote address), each listed with its row.
