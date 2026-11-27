// Added to github.com/coredns/coredns/test with `go test -overlay`.
//
// The test helpers' Input reports the server type "kerndns-compat" (see
// server.go), so caddy.Start and Instance.Restart on it come here instead
// of building an in-process CoreDNS. The first start runs the KernDNS
// binary with -control and hands it the Corefile on stdin; a Restart sends
// the new Corefile to the same process, which loads it in place like a
// CoreDNS reload (listeners with the same address keep their sockets) and
// reports the result. The caddy instances are real; their servers stand in
// for the KernDNS listeners, report the addresses KernDNS printed and stop
// the process when caddy stops the current instance.

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
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/metrics"
)

const kerndnsServerType = "kerndns-compat"

func init() {
	caddy.RegisterServerType(kerndnsServerType, caddy.ServerType{
		Directives: func() []string { return nil },
		NewContext: func(inst *caddy.Instance) caddy.Context { return &kerndnsContext{inst: inst} },
	})
}

// restartFrom is the process of the instance being restarted: set by the
// instance's OnRestart callback, taken by the new instance's MakeServers.
var (
	restartMu   sync.Mutex
	restartFrom *kerndnsProcess
)

type kerndnsContext struct{ inst *caddy.Instance }

func (*kerndnsContext) InspectServerBlocks(_ string, sb []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error) {
	return sb, nil
}

func (c *kerndnsContext) MakeServers() ([]caddy.Server, error) {
	in, ok := c.inst.Caddyfile().(*Input)
	if !ok {
		return nil, fmt.Errorf("kerndns: unexpected input %T", c.inst.Caddyfile())
	}
	restartMu.Lock()
	from := restartFrom
	restartFrom = nil
	restartMu.Unlock()

	var (
		g   *generation
		err error
	)
	if from != nil {
		g, err = from.reload(string(in.corefile))
	} else {
		recordUse()
		g, err = kerndnsStart(string(in.corefile))
	}
	if err != nil {
		return nil, err
	}
	p := g.proc
	c.inst.OnRestart = append(c.inst.OnRestart, func() error {
		restartMu.Lock()
		restartFrom = p
		restartMu.Unlock()
		return nil
	})
	c.inst.OnRestartFailed = append(c.inst.OnRestartFailed, func() error {
		restartMu.Lock()
		restartFrom = nil
		restartMu.Unlock()
		return nil
	})
	if len(g.servers) == 0 && from == nil {
		// Nothing for caddy to stop; tie the process to the test binary's life.
		p.stop()
	}
	return g.servers, nil
}

// report is what KernDNS printed after loading a Corefile.
type report struct {
	listeners []listenerLine
	metrics   []string
	err       error
}

type listenerLine struct{ label, udp, tcp string }

// kerndnsProcess is one running KernDNS binary.
type kerndnsProcess struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stderr  *strings.Builder
	reports chan report
	exited  chan struct{}
	done    chan struct{} // closed once the process is stopped

	mu      sync.Mutex // serializes reloads and stop
	current *generation
	once    sync.Once
}

// generation is the set of servers for one loaded Corefile. Stopping a
// generation that a reload replaced only ends its stand-in servers, as
// stopping the old instance after a CoreDNS restart leaves the listeners
// the new one took over.
type generation struct {
	proc    *kerndnsProcess
	servers []caddy.Server
	retired chan struct{}
	once    sync.Once
}

func (g *generation) stop() {
	p := g.proc
	p.mu.Lock()
	current := p.current == g
	p.mu.Unlock()
	if current {
		p.stop()
	}
	g.once.Do(func() { close(g.retired) })
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

func (p *kerndnsProcess) send(corefile string) error {
	_, err := fmt.Fprintf(p.stdin, "KERNDNS_COREFILE %d\n%s", len(corefile), corefile)
	return err
}

// wait returns the next report, or an error if the process exits first.
func (p *kerndnsProcess) wait() (report, error) {
	select {
	case r, ok := <-p.reports:
		if ok {
			return r, nil
		}
	case <-time.After(20 * time.Second):
		return report{}, errors.New("kerndns did not report within 20s")
	}
	<-p.exited
	msg := strings.TrimSpace(p.stderr.String())
	if msg == "" {
		msg = "kerndns exited"
	}
	return report{}, errors.New(msg)
}

// reload loads corefile into the running process, like Instance.Restart.
// On failure the process keeps its configuration.
func (p *kerndnsProcess) reload(corefile string) (*generation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
		return nil, errors.New("kerndns: instance was stopped")
	default:
	}
	if err := p.send(corefile); err != nil {
		return nil, fmt.Errorf("kerndns: sending Corefile: %w", err)
	}
	r, err := p.wait()
	if err == nil {
		err = r.err
	}
	if err != nil {
		return nil, err
	}
	g, err := p.newGeneration(r)
	if err != nil {
		return nil, err
	}
	p.current = g
	return g, nil
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

func kerndnsStart(corefile string) (*generation, error) {
	bin := os.Getenv("KERNDNS_BIN")
	if bin == "" {
		return nil, errors.New("KERNDNS_BIN is not set; run the tests with `cargo xtask compat-test`")
	}

	// The Corefile goes in on stdin, so relative paths in it resolve against
	// the test's working directory, as they do for the in-process server.
	// dnsserver.Port is the default port, as for in-process CoreDNS
	cmd := exec.Command(bin, "-control", "-quiet", "-report-listeners", "-dns.port", dnsserver.Port)
	if caddy.AppName != "" {
		// chaos answers with the embedding program's name and version, as
		// CoreDNS's does with caddy.AppName and caddy.AppVersion
		cmd.Env = append(os.Environ(), "KERNDNS_CHAOS_VERSION="+caddy.AppName+"-"+caddy.AppVersion)
	}
	// don't outlive the test binary if a test never calls Stop
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stderr := &strings.Builder{}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", bin, err)
	}
	p := &kerndnsProcess{
		cmd:     cmd,
		stdin:   stdin,
		stderr:  stderr,
		reports: make(chan report, 1),
		exited:  make(chan struct{}),
		done:    make(chan struct{}),
	}
	go p.readReports(stdout)
	go func() {
		_ = cmd.Wait()
		close(p.exited)
	}()

	if err := p.send(corefile); err != nil {
		p.stop()
		return nil, fmt.Errorf("kerndns: sending Corefile: %w", err)
	}
	r, err := p.wait()
	if err != nil {
		p.stop()
		return nil, err
	}
	g, err := p.newGeneration(r)
	if err != nil {
		p.stop()
		return nil, err
	}
	p.mu.Lock()
	p.current = g
	p.mu.Unlock()
	return g, nil
}

// readReports turns KernDNS's -report-listeners output into reports.
func (p *kerndnsProcess) readReports(stdout io.Reader) {
	sc := bufio.NewScanner(stdout)
	verbose := os.Getenv("KERNDNS_COMPAT_VERBOSE") != ""
	var r report
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "KERNDNS_READY":
			p.reports <- r
			r = report{}
		case strings.HasPrefix(line, "KERNDNS_RELOAD_FAILED "):
			p.reports <- report{err: errors.New(strings.TrimPrefix(line, "KERNDNS_RELOAD_FAILED "))}
			r = report{}
		case strings.HasPrefix(line, "KERNDNS_METRICS "):
			r.metrics = append(r.metrics, strings.TrimPrefix(line, "KERNDNS_METRICS "))
		case strings.HasPrefix(line, "KERNDNS_LISTENER "):
			f := strings.Fields(strings.TrimPrefix(line, "KERNDNS_LISTENER "))
			if len(f) == 3 {
				r.listeners = append(r.listeners, listenerLine{
					label: f[0],
					udp:   strings.TrimPrefix(f[1], "udp="),
					tcp:   strings.TrimPrefix(f[2], "tcp="),
				})
			}
		default:
			if verbose {
				fmt.Println(line)
			}
		}
	}
	close(p.reports)
	_, _ = io.Copy(io.Discard, stdout)
}

func (p *kerndnsProcess) newGeneration(r report) (*generation, error) {
	for _, m := range r.metrics {
		// tests scrape metrics.ListenAddr, which in-process CoreDNS sets
		metrics.ListenAddr = m
	}
	g := &generation{proc: p, retired: make(chan struct{})}
	for _, l := range r.listeners {
		// A listener without UDP (DoT, DoH, gRPC) or without TCP (DoQ,
		// DoH3) reports an empty address, which stays nil, as the CoreDNS
		// server's Listen or ListenPacket returns nil.
		var udp, tcp net.Addr
		if l.udp != "" {
			a, err := net.ResolveUDPAddr("udp", l.udp)
			if err != nil {
				return nil, fmt.Errorf("bad udp address %q: %w", l.udp, err)
			}
			udp = a
		}
		if l.tcp != "" {
			a, err := net.ResolveTCPAddr("tcp", l.tcp)
			if err != nil {
				return nil, fmt.Errorf("bad tcp address %q: %w", l.tcp, err)
			}
			tcp = a
		}
		g.servers = append(g.servers, &kerndnsServer{label: l.label, gen: g, udp: udp, tcp: tcp})
	}
	return g, nil
}

// kerndnsServer implements caddy.GracefulServer for one KernDNS listener.
type kerndnsServer struct {
	label string
	gen   *generation
	udp   net.Addr
	tcp   net.Addr
}

func (s *kerndnsServer) Listen() (net.Listener, error) {
	if s.tcp == nil {
		return nil, nil
	}
	return &fakeListener{addr: s.tcp, gen: s.gen}, nil
}

func (s *kerndnsServer) ListenPacket() (net.PacketConn, error) {
	if s.udp == nil {
		return nil, nil
	}
	return &fakePacketConn{addr: s.udp, gen: s.gen}, nil
}

func (s *kerndnsServer) Serve(net.Listener) error                 { s.gen.wait(); return nil }
func (s *kerndnsServer) ServePacket(net.PacketConn) error         { s.gen.wait(); return nil }
func (s *kerndnsServer) Stop() error                              { s.gen.stop(); return nil }
func (s *kerndnsServer) Address() string                          { return s.label }
func (s *kerndnsServer) WrapListener(l net.Listener) net.Listener { return l }

// wait blocks until the generation is stopped or the process ends.
func (g *generation) wait() {
	select {
	case <-g.retired:
	case <-g.proc.done:
	}
}

var errStopped = errors.New("use of closed network connection")

type fakeListener struct {
	addr net.Addr
	gen  *generation
}

func (l *fakeListener) Accept() (net.Conn, error) { l.gen.wait(); return nil, errStopped }
func (l *fakeListener) Close() error              { return nil }
func (l *fakeListener) Addr() net.Addr            { return l.addr }

type fakePacketConn struct {
	addr net.Addr
	gen  *generation
}

func (c *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.gen.wait()
	return 0, nil, errStopped
}
func (c *fakePacketConn) WriteTo([]byte, net.Addr) (int, error) { return 0, errStopped }
func (c *fakePacketConn) Close() error                          { return nil }
func (c *fakePacketConn) LocalAddr() net.Addr                   { return c.addr }
func (c *fakePacketConn) SetDeadline(time.Time) error           { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error       { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error      { return nil }
