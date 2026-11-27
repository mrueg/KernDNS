// Added to github.com/coredns/coredns/test with `go test -overlay`.
//
// kerndnsStart runs the KernDNS binary with a Corefile and returns a real
// *caddy.Instance whose servers stand in for the KernDNS listeners, so the
// upstream tests can call i.Servers(), i.Stop() and the port helpers
// unchanged. The fake servers report the addresses KernDNS printed and stop
// the process when caddy stops them.

package test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/caddy/caddyfile"
	"github.com/coredns/coredns/plugin/metrics"
)

const kerndnsServerType = "kerndns-compat"

// pendingServers is handed from kerndnsStart to MakeServers; both run under mu.
var pendingServers []caddy.Server

func init() {
	caddy.RegisterServerType(kerndnsServerType, caddy.ServerType{
		Directives: func() []string { return nil },
		NewContext: func(*caddy.Instance) caddy.Context { return kerndnsContext{} },
	})
}

type kerndnsContext struct{}

func (kerndnsContext) InspectServerBlocks(_ string, sb []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error) {
	return sb, nil
}

func (kerndnsContext) MakeServers() ([]caddy.Server, error) {
	s := pendingServers
	pendingServers = nil
	return s, nil
}

type emptyInput struct{}

func (emptyInput) Body() []byte       { return nil }
func (emptyInput) Path() string       { return "kerndns" }
func (emptyInput) ServerType() string { return kerndnsServerType }

// kerndnsProcess is one running KernDNS binary.
type kerndnsProcess struct {
	cmd    *exec.Cmd
	exited chan struct{}
	once   sync.Once
	done   chan struct{}
}

func (p *kerndnsProcess) stop() {
	p.once.Do(func() {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.exited:
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.exited
		}
		close(p.done)
	})
}

// callingTest returns the name of the Test function on the stack, if any.
func callingTest() string {
	pcs := make([]uintptr, 64)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if i := strings.LastIndex(f.Function, ".Test"); i >= 0 && strings.HasPrefix(f.Function, "github.com/coredns/coredns/test.") {
			name := f.Function[i+1:]
			if j := strings.IndexAny(name, ".("); j >= 0 {
				name = name[:j]
			}
			return name
		}
		if !more {
			return ""
		}
	}
}

// recordUse appends the calling test's name to $KERNDNS_COMPAT_TRACE, so the
// runner can tell tests that really exercised KernDNS from tests that never
// started it (and would pass or fail on their own).
func recordUse() {
	path := os.Getenv("KERNDNS_COMPAT_TRACE")
	if path == "" {
		return
	}
	name := callingTest()
	if name == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, name)
}

func kerndnsStart(corefile string) (*caddy.Instance, error) {
	recordUse()
	bin := os.Getenv("KERNDNS_BIN")
	if bin == "" {
		return nil, errors.New("KERNDNS_BIN is not set; run the tests with `cargo xtask compat-test`")
	}

	// The Corefile goes in on stdin, so relative paths in it resolve against
	// the test's working directory, as they do for the in-process server.
	cmd := exec.Command(bin, "-conf", "stdin", "-quiet", "-report-listeners")
	cmd.Stdin = strings.NewReader(corefile)
	// don't outlive the test binary if a test never calls Stop
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", bin, err)
	}
	proc := &kerndnsProcess{cmd: cmd, exited: make(chan struct{}), done: make(chan struct{})}

	type listener struct{ label, udp, tcp string }
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(stdout)
		ready := false
		for sc.Scan() {
			if !ready {
				lines <- sc.Text()
				ready = sc.Text() == "KERNDNS_READY"
				continue
			}
			if os.Getenv("KERNDNS_COMPAT_VERBOSE") != "" {
				fmt.Println(sc.Text())
			}
		}
		if !ready {
			close(lines)
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	go func() {
		_ = cmd.Wait()
		close(proc.exited)
	}()

	var listeners []listener
	timeout := time.After(20 * time.Second)
wait:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				<-proc.exited
				msg := strings.TrimSpace(stderr.String())
				if msg == "" {
					msg = "kerndns exited before it was ready"
				}
				return nil, errors.New(msg)
			}
			if line == "KERNDNS_READY" {
				break wait
			}
			if rest, ok := strings.CutPrefix(line, "KERNDNS_METRICS "); ok {
				// tests scrape metrics.ListenAddr, which in-process CoreDNS sets
				metrics.ListenAddr = rest
				continue
			}
			if rest, ok := strings.CutPrefix(line, "KERNDNS_LISTENER "); ok {
				f := strings.Fields(rest)
				if len(f) == 3 {
					listeners = append(listeners, listener{
						label: f[0],
						udp:   strings.TrimPrefix(f[1], "udp="),
						tcp:   strings.TrimPrefix(f[2], "tcp="),
					})
				}
			}
		case <-timeout:
			proc.stop()
			return nil, errors.New("kerndns did not become ready within 20s")
		}
	}

	servers := make([]caddy.Server, 0, len(listeners))
	for _, l := range listeners {
		udp, err := net.ResolveUDPAddr("udp", l.udp)
		if err != nil {
			proc.stop()
			return nil, fmt.Errorf("bad udp address %q: %w", l.udp, err)
		}
		tcp, err := net.ResolveTCPAddr("tcp", l.tcp)
		if err != nil {
			proc.stop()
			return nil, fmt.Errorf("bad tcp address %q: %w", l.tcp, err)
		}
		servers = append(servers, &kerndnsServer{label: l.label, proc: proc, udp: udp, tcp: tcp})
	}
	pendingServers = servers
	inst, err := caddy.Start(emptyInput{})
	if err != nil {
		proc.stop()
		return nil, err
	}
	if len(servers) == 0 {
		// Nothing for caddy to stop; tie the process to the test binary's life.
		proc.stop()
	}
	return inst, nil
}

// kerndnsServer implements caddy.GracefulServer for one KernDNS listener.
type kerndnsServer struct {
	label string
	proc  *kerndnsProcess
	udp   net.Addr
	tcp   net.Addr
}

func (s *kerndnsServer) Listen() (net.Listener, error) {
	return &fakeListener{addr: s.tcp, done: s.proc.done}, nil
}

func (s *kerndnsServer) ListenPacket() (net.PacketConn, error) {
	return &fakePacketConn{addr: s.udp, done: s.proc.done}, nil
}

func (s *kerndnsServer) Serve(net.Listener) error                 { <-s.proc.done; return nil }
func (s *kerndnsServer) ServePacket(net.PacketConn) error         { <-s.proc.done; return nil }
func (s *kerndnsServer) Stop() error                              { s.proc.stop(); return nil }
func (s *kerndnsServer) Address() string                          { return s.label }
func (s *kerndnsServer) WrapListener(l net.Listener) net.Listener { return l }

var errStopped = errors.New("use of closed network connection")

type fakeListener struct {
	addr net.Addr
	done chan struct{}
}

func (l *fakeListener) Accept() (net.Conn, error) { <-l.done; return nil, errStopped }
func (l *fakeListener) Close() error              { return nil }
func (l *fakeListener) Addr() net.Addr            { return l.addr }

type fakePacketConn struct {
	addr net.Addr
	done chan struct{}
}

func (c *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { <-c.done; return 0, nil, errStopped }
func (c *fakePacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, errStopped }
func (c *fakePacketConn) Close() error                           { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                    { return c.addr }
func (c *fakePacketConn) SetDeadline(time.Time) error            { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error        { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error       { return nil }
