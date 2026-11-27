// Added to github.com/coredns/coredns/plugin/kubernetes with
// `go test -overlay` by `cargo xtask k8s-cases`.
//
// Runs the plugin's own handler test suites against the Go implementation
// and writes the fake API objects, every query, every upstream lookup the
// plugin made and the exact response it produced to $KERNDNS_K8S_DUMP.
// KernDNS's Rust port replays the same queries against the same data and
// must produce the same responses.

package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/kubernetes/object"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

type dumpRR = string // hex of the uncompressed wire RR

type dumpMsg struct {
	Rcode  int      `json:"rcode"`
	AA     bool     `json:"aa"`
	TC     bool     `json:"tc"`
	Answer []dumpRR `json:"answer"`
	Ns     []dumpRR `json:"ns"`
	Extra  []dumpRR `json:"extra"`
}

type dumpLookup struct {
	Name     string  `json:"name"`
	Qtype    uint16  `json:"qtype"`
	Response dumpMsg `json:"response"`
}

type dumpCase struct {
	Qname      string       `json:"qname"`
	Qtype      uint16       `json:"qtype"`
	Do         bool         `json:"do"`
	Upstream   []dumpLookup `json:"upstream"`
	Response   *dumpMsg     `json:"response"` // nil: nothing written (next plugin)
	ReturnCode int          `json:"return_code"`
	Error      string       `json:"error"`
}

type dumpSuite struct {
	Name               string     `json:"name"`
	Zones              []string   `json:"zones"`
	Namespaces         []string   `json:"namespaces"`
	PodMode            string     `json:"pod_mode"`
	IgnoreEmptyService bool       `json:"ignore_empty_service"`
	NotSynced          bool       `json:"not_synced"`
	LocalIPs           []string   `json:"local_ips"`
	Cases              []dumpCase `json:"cases"`
}

type dumpData struct {
	Services          map[string][]*object.Service   `json:"services"`
	Endpoints         map[string][]*object.Endpoints `json:"endpoints"`
	Pods              []*object.Pod                  `json:"pods"`
	MissingNamespaces []string                       `json:"missing_namespaces"`
	Suites            []dumpSuite                    `json:"suites"`
	Transfers         []dumpXfr                      `json:"transfers"`
}

// dumpXfr is one Transfer call (xfr_test.go) and the records it streamed.
type dumpXfr struct {
	Name       string   `json:"name"`
	Zones      []string `json:"zones"`
	Namespaces []string `json:"namespaces"`
	LocalIPs   []string `json:"local_ips"`
	Zone       string   `json:"zone"`
	Serial     uint32   `json:"serial"`
	Error      string   `json:"error"`
	Records    []dumpRR `json:"records"`
}

func runXfr(name string, localIPs []string, zone string, serial uint32) dumpXfr {
	k := New([]string{"cluster.local."})
	k.APIConn = &APIConnServeTest{}
	k.Namespaces = map[string]struct{}{"testns": {}, "kube-system": {}}
	for _, ip := range localIPs {
		k.localIPs = append(k.localIPs, net.ParseIP(ip))
	}
	x := dumpXfr{Name: name, Zones: k.Zones, Namespaces: []string{"kube-system", "testns"}, LocalIPs: localIPs, Zone: zone, Serial: serial, Records: []dumpRR{}}
	ch, err := k.Transfer(zone, serial)
	if err != nil {
		x.Error = err.Error()
		return x
	}
	for rrs := range ch {
		x.Records = append(x.Records, packRRs(rrs)...)
	}
	return x
}

func packRRs(rrs []dns.RR) []dumpRR {
	out := []dumpRR{}
	for _, rr := range rrs {
		buf := make([]byte, dns.Len(rr)+256)
		n, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			panic(err)
		}
		out = append(out, hex.EncodeToString(buf[:n]))
	}
	return out
}

func toDump(m *dns.Msg) dumpMsg {
	extra := []dns.RR{}
	for _, rr := range m.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			extra = append(extra, rr)
		}
	}
	return dumpMsg{Rcode: m.Rcode, AA: m.Authoritative, TC: m.Truncated, Answer: packRRs(m.Answer), Ns: packRRs(m.Ns), Extra: packRRs(extra)}
}

// recordingUpstream remembers what the plugin asked its upstream.
type recordingUpstream struct {
	inner Upstreamer
	seen  []dumpLookup
}

func (r *recordingUpstream) Lookup(ctx context.Context, state request.Request, name string, typ uint16) (*dns.Msg, error) {
	m, err := r.inner.Lookup(ctx, state, name, typ)
	if err == nil && m != nil {
		r.seen = append(r.seen, dumpLookup{Name: strings.ToLower(name), Qtype: typ, Response: toDump(m)})
	}
	return m, err
}

func runSuite(name string, k *Kubernetes, cases []kubeTestCase, notSynced bool) dumpSuite {
	s := dumpSuite{Name: name, Zones: k.Zones, PodMode: k.podMode, IgnoreEmptyService: k.opts.ignoreEmptyService, NotSynced: notSynced}
	for ns := range k.Namespaces {
		s.Namespaces = append(s.Namespaces, ns)
	}
	sort.Strings(s.Namespaces)
	for _, ip := range k.localIPs {
		s.LocalIPs = append(s.LocalIPs, ip.String())
	}
	k.Next = test.NextHandler(dns.RcodeSuccess, nil)
	for _, tc := range cases {
		var rec *recordingUpstream
		if tc.Upstream != nil {
			rec = &recordingUpstream{inner: tc.Upstream}
			k.Upstream = rec
		} else {
			k.Upstream = nil
		}
		r := tc.Msg()
		w := dnstest.NewRecorder(&test.ResponseWriter{})
		rc, err := k.ServeDNS(context.TODO(), w, r)
		c := dumpCase{Qname: tc.Qname, Qtype: tc.Qtype, Do: tc.Do, ReturnCode: rc, Upstream: []dumpLookup{}}
		if rec != nil {
			c.Upstream = rec.seen
		}
		if err != nil {
			c.Error = err.Error()
		}
		if w.Msg != nil {
			d := toDump(w.Msg)
			c.Response = &d
		}
		s.Cases = append(s.Cases, c)
	}
	return s
}

func wrap(cs []test.Case) []kubeTestCase {
	out := make([]kubeTestCase, len(cs))
	for i, c := range cs {
		out[i] = kubeTestCase{Case: c}
	}
	return out
}

func TestKernDNSDump(t *testing.T) {
	path := os.Getenv("KERNDNS_K8S_DUMP")
	if path == "" {
		t.Skip("KERNDNS_K8S_DUMP not set")
	}
	d := dumpData{Services: svcIndex, Endpoints: epsIndex, MissingNamespaces: []string{"pod-nons", "nsnoexist"}}
	d.Pods = APIConnServeTest{}.PodIndex("10.240.0.1")

	base := func() *Kubernetes {
		k := New([]string{"cluster.local."})
		k.APIConn = &APIConnServeTest{}
		return k
	}

	k := base()
	k.Namespaces = map[string]struct{}{"testns": {}}
	d.Suites = append(d.Suites, runSuite("serve", k, append(commonDnsTestCases, dnsTestCases...), false))

	k = base()
	k.Namespaces = map[string]struct{}{}
	d.Suites = append(d.Suites, runSuite("namespaces", k, wrap(nsTestCases), false))

	k = base()
	k.APIConn = &APIConnServeTest{notSynced: true}
	k.Namespaces = map[string]struct{}{"testns": {}}
	d.Suites = append(d.Suites, runSuite("not_synced", k, wrap(notSyncedTestCases), true))

	for _, m := range []struct {
		name  string
		mode  string
		cases []test.Case
	}{
		{"pods_disabled", podModeDisabled, podModeDisabledCases},
		{"pods_insecure", podModeInsecure, podModeInsecureCases},
		{"pods_verified", podModeVerified, podModeVerifiedCases},
	} {
		k = base()
		k.podMode = m.mode
		d.Suites = append(d.Suites, runSuite(m.name, k, wrap(m.cases), false))
	}

	k = base()
	k.opts.ignoreEmptyService = true
	d.Suites = append(d.Suites, runSuite("ignore_empty_service", k, wrap(dnsEmptyServiceTestCases), false))

	k = base()
	k.localIPs = []net.IP{net.ParseIP("127.0.0.1")}
	d.Suites = append(d.Suites, runSuite("apex", k, wrap(kubeApexCases), false))

	k = base()
	k.opts.ignoreEmptyService = true
	d.Suites = append(d.Suites, runSuite("preserve_case", k, wrap(dnsPreserveCaseCases), false))

	// xfr_test.go
	d.Transfers = append(d.Transfers,
		runXfr("non_auth_zone", []string{"10.0.0.10"}, "example.com.", 0),
		runXfr("axfr", []string{"10.0.0.10"}, "cluster.local.", 0),
		runXfr("ixfr_fallback", []string{"10.0.0.10"}, "cluster.local.", 1),
		runXfr("ixfr_current", []string{"10.0.0.10"}, "cluster.local.", 3),
		runXfr("axfr_multiple_ns_addrs", []string{"10.0.0.10", "fd00::10"}, "cluster.local.", 0),
	)

	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
