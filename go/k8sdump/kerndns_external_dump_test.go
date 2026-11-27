// Added to github.com/coredns/coredns/plugin/k8s_external with
// `go test -overlay` by `cargo xtask k8s-cases`.
//
// Runs the plugin's own test cases (external_test.go, apex_test.go) and
// transfers (transfer_test.go) against the Go implementation and writes the
// fake API objects, every query, the exact response and the transferred
// records to $KERNDNS_K8S_EXTERNAL_DUMP. KernDNS's Rust port replays them.

package external

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/coredns/coredns/plugin/kubernetes"
	"github.com/coredns/coredns/plugin/kubernetes/object"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

type extDumpMsg struct {
	Rcode  int      `json:"rcode"`
	AA     bool     `json:"aa"`
	Answer []string `json:"answer"`
	Ns     []string `json:"ns"`
	Extra  []string `json:"extra"`
}

type extDumpCase struct {
	Qname    string      `json:"qname"`
	Qtype    uint16      `json:"qtype"`
	Response *extDumpMsg `json:"response"`
	Error    string      `json:"error"`
}

type extDumpSuite struct {
	Name  string        `json:"name"`
	Zones []string      `json:"zones"`
	Cases []extDumpCase `json:"cases"`
}

type extDumpXfr struct {
	Name    string   `json:"name"`
	Zone    string   `json:"zone"`
	Serial  uint32   `json:"serial"`
	Records []string `json:"records"`
}

type extDumpData struct {
	Services  map[string][]*object.Service   `json:"services"`
	Endpoints map[string][]*object.Endpoints `json:"endpoints"`
	Serial    uint32                         `json:"serial"`
	Suites    []extDumpSuite                 `json:"suites"`
	Transfers []extDumpXfr                   `json:"transfers"`
}

func extPack(rrs []dns.RR) []string {
	out := []string{}
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		buf := make([]byte, dns.Len(rr)+256)
		n, err := dns.PackRR(rr, buf, 0, nil, false)
		if err != nil {
			panic(err)
		}
		out = append(out, hex.EncodeToString(buf[:n]))
	}
	return out
}

func newDumpExternal(zones []string) *External {
	k := kubernetes.New([]string{"cluster.local."})
	k.Namespaces = map[string]struct{}{"testns": {}}
	k.APIConn = &external{}

	e := New()
	e.Zones = zones
	e.headless = true
	e.Next = test.NextHandler(dns.RcodeSuccess, nil)
	e.externalFunc = k.External
	e.externalAddrFunc = externalAddress
	e.externalSerialFunc = externalSerial
	e.externalServicesFunc = k.ExternalServices
	return e
}

func runExtSuite(name string, zones []string, cases []test.Case) extDumpSuite {
	e := newDumpExternal(zones)
	s := extDumpSuite{Name: name, Zones: zones}
	for _, tc := range cases {
		w := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := e.ServeDNS(context.TODO(), w, tc.Msg())
		c := extDumpCase{Qname: tc.Qname, Qtype: tc.Qtype}
		if err != nil {
			c.Error = err.Error()
		}
		if w.Msg != nil {
			c.Response = &extDumpMsg{Rcode: w.Msg.Rcode, AA: w.Msg.Authoritative, Answer: extPack(w.Msg.Answer), Ns: extPack(w.Msg.Ns), Extra: extPack(w.Msg.Extra)}
		}
		s.Cases = append(s.Cases, c)
	}
	return s
}

func runExtXfr(name, zone string, serial uint32) extDumpXfr {
	e := newDumpExternal([]string{"example.com."})
	x := extDumpXfr{Name: name, Zone: zone, Serial: serial, Records: []string{}}
	ch, err := e.Transfer(zone, serial)
	if err != nil {
		panic(err)
	}
	for rrs := range ch {
		x.Records = append(x.Records, extPack(rrs)...)
	}
	return x
}

func TestKernDNSExternalDump(t *testing.T) {
	path := os.Getenv("KERNDNS_K8S_EXTERNAL_DUMP")
	if path == "" {
		t.Skip("KERNDNS_K8S_EXTERNAL_DUMP not set")
	}
	d := extDumpData{Services: svcIndexExternal, Endpoints: epIndexExternal, Serial: externalSerial("")}
	d.Suites = append(d.Suites,
		runExtSuite("external", []string{"example.com.", "in-addr.arpa."}, tests),
		runExtSuite("apex", []string{"example.com."}, testsApex),
	)
	d.Transfers = append(d.Transfers,
		runExtXfr("axfr", "example.com.", 0),
		runExtXfr("ixfr", "example.com.", externalSerial("example.com.")),
	)
	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
