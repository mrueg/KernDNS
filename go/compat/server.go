// Replacement for github.com/coredns/coredns/test/server.go, swapped in with
// `go test -overlay`. The helpers keep their signatures, but by default the
// server they start is the KernDNS binary ($KERNDNS_BIN) instead of an
// in-process CoreDNS: Input reports the "kerndns-compat" server type (see
// kerndns_compat.go), so caddy.Start and Instance.Restart with it start or
// reload KernDNS. Set KERNDNS_COMPAT_TARGET=coredns to run the original
// in-process CoreDNS, which checks the harness itself.

package test

import (
	"os"
	"sync"

	"github.com/coredns/caddy"
	_ "github.com/coredns/coredns/core" // Hook in CoreDNS.
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/core/plugin" // Load all managed plugins in github.com/coredns/coredns.
)

var mu sync.Mutex

// targetCoreDNS is true when the tests run against in-process CoreDNS.
var targetCoreDNS = os.Getenv("KERNDNS_COMPAT_TARGET") == "coredns"

// CoreDNSServer returns a test server. It just takes a normal Corefile as input.
func CoreDNSServer(corefile string) (*caddy.Instance, error) {
	mu.Lock()
	defer mu.Unlock()
	caddy.Quiet = true
	dnsserver.Quiet = true

	return caddy.Start(NewInput(corefile))
}

// CoreDNSServerStop stops a server.
func CoreDNSServerStop(i *caddy.Instance) { i.Stop() }

// CoreDNSServerPorts returns the ports the instance is listening on. The integer k indicates
// which ServerListener you want.
func CoreDNSServerPorts(i *caddy.Instance, k int) (udp, tcp string) {
	srvs := i.Servers()
	if len(srvs) < k+1 {
		return "", ""
	}
	u := srvs[k].LocalAddr()
	t := srvs[k].Addr()

	if u != nil {
		udp = u.String()
	}
	if t != nil {
		tcp = t.String()
	}
	return
}

// CoreDNSServerAndPorts combines CoreDNSServer and CoreDNSServerPorts to start a server
// and returns the udp and tcp ports of the first instance.
func CoreDNSServerAndPorts(corefile string) (i *caddy.Instance, udp, tcp string, err error) {
	i, err = CoreDNSServer(corefile)
	if err != nil {
		return nil, "", "", err
	}
	udp, tcp = CoreDNSServerPorts(i, 0)
	return i, udp, tcp, nil
}

// Input implements the caddy.Input interface and acts as an easy way to use a string as a Corefile.
type Input struct {
	corefile []byte
}

// NewInput returns a pointer to Input, containing the corefile string as input.
func NewInput(corefile string) *Input {
	return &Input{corefile: []byte(corefile)}
}

// Body implements the Input interface. For KernDNS it is empty, as caddy
// parses the body with its own Corefile parser before handing it to the
// server type; KernDNS gets i.corefile and parses it itself.
func (i *Input) Body() []byte {
	if targetCoreDNS {
		return i.corefile
	}
	return nil
}

// Path implements the Input interface.
func (i *Input) Path() string { return "Corefile" }

// ServerType implements the Input interface.
func (i *Input) ServerType() string {
	if targetCoreDNS {
		return "dns"
	}
	return kerndnsServerType
}
