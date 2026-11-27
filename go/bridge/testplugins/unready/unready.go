// Package unready holds the perpetually unready plugins that CoreDNS's
// TestReloadUnreadyPlugin and TestReloadTwoServerBlocksUnreadyPlugin
// (test/reload_test.go) register inside the test binary. `cargo xtask
// compat-test` builds them into a Go bridge so those tests run against
// KernDNS: its `ready` sees their Ready() through the bridge.
//
// As in the tests, the directives go first in dnsserver.Directives.
package unready

import (
	"context"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

var names = []string{"unready", "unready1", "unready2"}

func init() {
	dnsserver.Directives = append(append([]string{}, names...), dnsserver.Directives...)
	for _, name := range names {
		plugin.Register(name, func(c *caddy.Controller) error {
			u := &unready{name: name}
			dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
				u.next = next
				return u
			})
			return nil
		})
	}
}

// unready is the test's plugin: it never becomes ready and passes every
// query on.
type unready struct {
	next plugin.Handler
	name string
}

func (u *unready) Ready() bool { return false }

func (u *unready) Name() string { return u.name }

func (u *unready) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	return u.next.ServeDNS(ctx, w, r)
}
