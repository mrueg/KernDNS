// Package main is the KernDNS Go bridge: a c-shared library that runs
// CoreDNS plugins (compiled in through plugins_gen.go) inside a KernDNS
// plugin chain. The C interface is described in docs/PLAN.md ("Go bridge").
//
// Each directive is set up with a throwaway caddy controller, the way
// CoreDNS's own tests do. Its handler is wrapped around rustNext, which
// hands the request back to the Rust chain and parks the goroutine until
// Rust answers, so no OS thread is ever blocked inside a callback.
package main

/*
#include <stdlib.h>
#include "callbacks.h"
*/
import "C"

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/ready"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

func main() {}

// instance is one set-up directive.
type instance struct {
	name    string
	handler plugin.Handler
	caddy   *caddy.Instance
}

var (
	handles   sync.Map // int64 -> *instance
	nextID    atomic.Int64
	waits     sync.Map // uint64 -> chan nextResult
	nextToken atomic.Uint64
)

type tokenKey struct{}

type nextResult struct {
	rcode int
	msgs  [][]byte
	err   string
}

func cstr(s string) *C.char { return C.CString(s) }

func bytesPtr(b []byte) (*C.uint8_t, C.size_t) {
	if len(b) == 0 {
		return nil, 0
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0])), C.size_t(len(b))
}

//export kb_version
func kb_version() C.int { return 1 }

//export kb_init
func kb_init(w C.kb_write_fn, n C.kb_next_fn, d C.kb_done_fn) {
	C.kb_set_callbacks(w, n, d)
}

//export kb_free
func kb_free(p *C.char) { C.free(unsafe.Pointer(p)) }

// kb_list_plugins returns the directives compiled into the bridge (JSON).
//
//export kb_list_plugins
func kb_list_plugins() *C.char {
	out := []string{}
	for _, n := range caddy.ListPlugins()["others"] {
		// server type plugins are listed as "dns.etcd"
		if name, ok := strings.CutPrefix(n, "dns."); ok {
			out = append(out, name)
		}
	}
	b, _ := json.Marshal(out)
	return cstr(string(b))
}

// caddyInstance digs the instance out of a test controller; caddy keeps
// it unexported, but its hooks (OnStartup, ...) are what we need to run.
func caddyInstance(c *caddy.Controller) *caddy.Instance {
	f := reflect.ValueOf(c).Elem().FieldByName("instance")
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Interface().(*caddy.Instance)
}

// kb_setup runs the setup of directive name on input (the directive's
// Corefile text), for a server block with the given keys (JSON array).
// It returns a handle, or 0 and sets *errOut.
//
//export kb_setup
func kb_setup(name, input, keysJSON, root *C.char, errOut **C.char) C.longlong {
	h, err := setup(C.GoString(name), C.GoString(input), C.GoString(keysJSON), C.GoString(root))
	if err != nil {
		*errOut = cstr(err.Error())
		return 0
	}
	return C.longlong(h)
}

func setup(name, input, keysJSON, root string) (h int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("plugin/%s: setup panicked: %v", name, r)
		}
	}()
	var keys []string
	if err := json.Unmarshal([]byte(keysJSON), &keys); err != nil {
		return 0, err
	}
	action, err := caddy.DirectiveAction("dns", name)
	if err != nil {
		return 0, err
	}
	c := caddy.NewTestController("dns", input)
	c.ServerBlockKeys = keys
	cfg := dnsserver.GetConfig(c)
	cfg.Root = root
	if len(keys) > 0 {
		cfg.Zone = keys[0]
	}
	if err := action(c); err != nil {
		return 0, err
	}
	var handler plugin.Handler = rustNext{}
	for i := len(cfg.Plugin) - 1; i >= 0; i-- {
		handler = cfg.Plugin[i](handler)
	}
	id := nextID.Add(1)
	handles.Store(id, &instance{name: name, handler: handler, caddy: caddyInstance(c)})
	return id, nil
}

func get(h C.longlong) *instance {
	v, ok := handles.Load(int64(h))
	if !ok {
		return nil
	}
	return v.(*instance)
}

func runHooks(hooks []func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("hook panicked: %v", r)
		}
	}()
	for _, f := range hooks {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}

//export kb_startup
func kb_startup(h C.longlong, errOut **C.char) C.int {
	in := get(h)
	if in == nil {
		*errOut = cstr("unknown handle")
		return 1
	}
	if err := runHooks(append(append([]func() error{}, in.caddy.OnFirstStartup...), in.caddy.OnStartup...)); err != nil {
		*errOut = cstr(err.Error())
		return 1
	}
	return 0
}

//export kb_shutdown
func kb_shutdown(h C.longlong) C.int {
	in := get(h)
	if in == nil {
		return 1
	}
	err := runHooks(append(append([]func() error{}, in.caddy.OnShutdown...), in.caddy.OnFinalShutdown...))
	handles.Delete(int64(h))
	if err != nil {
		return 1
	}
	return 0
}

// kb_ready: 1 if the plugin is ready (or doesn't report readiness).
//
//export kb_ready
func kb_ready(h C.longlong) C.int {
	in := get(h)
	if in == nil {
		return 0
	}
	if r, ok := in.handler.(ready.Readiness); ok && !r.Ready() {
		return 0
	}
	return 1
}

// kb_gather_metrics encodes the Go registry for a scrape with the given
// Accept header (text or delimited protobuf, so the host can append it to
// its own output), without the go_ and process_ families the host already
// exports. It returns malloc'd bytes and sets *n and *contentType.
//
//export kb_gather_metrics
func kb_gather_metrics(accept *C.char, n *C.size_t, contentType **C.char) *C.uint8_t {
	g := prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
		mfs, err := prometheus.DefaultGatherer.Gather()
		out := mfs[:0]
		for _, mf := range mfs {
			name := mf.GetName()
			if strings.HasPrefix(name, "go_") || strings.HasPrefix(name, "process_") {
				continue
			}
			out = append(out, mf)
		}
		return out, err
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Accept", C.GoString(accept))
	promhttp.HandlerFor(g, promhttp.HandlerOpts{DisableCompression: true}).ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	*n = C.size_t(len(body))
	*contentType = cstr(rec.Header().Get("Content-Type"))
	return (*C.uint8_t)(C.CBytes(body))
}

func addr(s, proto string) net.Addr {
	host, port, _ := net.SplitHostPort(s)
	ip := net.ParseIP(host)
	p, _ := strconv.Atoi(port)
	if proto == "udp" {
		return &net.UDPAddr{IP: ip, Port: p}
	}
	return &net.TCPAddr{IP: ip, Port: p}
}

// kb_serve serves one request on handle h in a new goroutine; the result
// arrives through the write/next/done callbacks tagged with token.
//
//export kb_serve
func kb_serve(h C.longlong, token C.uint64_t, msg *C.uint8_t, n C.size_t, remote, local, proto, server, metaJSON *C.char) {
	in := get(h)
	buf := C.GoBytes(unsafe.Pointer(msg), C.int(n))
	t := uint64(token)
	rs, ls, ps, srv, mj := C.GoString(remote), C.GoString(local), C.GoString(proto), C.GoString(server), C.GoString(metaJSON)
	go serve(in, t, buf, rs, ls, ps, srv, mj)
}

// kb_serve_sync serves the request on the calling thread and returns
// when the handler has. The callbacks run on this thread too, so the host
// must answer a call to next before its callback returns.
//
//export kb_serve_sync
func kb_serve_sync(h C.longlong, token C.uint64_t, msg *C.uint8_t, n C.size_t, remote, local, proto, server, metaJSON *C.char) {
	in := get(h)
	buf := C.GoBytes(unsafe.Pointer(msg), C.int(n))
	serve(in, uint64(token), buf, C.GoString(remote), C.GoString(local), C.GoString(proto), C.GoString(server), C.GoString(metaJSON))
}

func done(token uint64, rcode int, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	c := cstr(msg)
	C.kb_call_done(C.uint64_t(token), C.int(rcode), c)
	C.free(unsafe.Pointer(c))
}

func serve(in *instance, token uint64, buf []byte, remote, local, proto, server, metaJSON string) {
	defer func() {
		if r := recover(); r != nil {
			done(token, dns.RcodeServerFailure, fmt.Errorf("panic in Go plugin: %v", r))
		}
	}()
	if in == nil {
		done(token, dns.RcodeServerFailure, errors.New("unknown bridge handle"))
		return
	}
	m := new(dns.Msg)
	if err := m.Unpack(buf); err != nil {
		done(token, dns.RcodeFormatError, err)
		return
	}
	ctx := context.WithValue(context.Background(), tokenKey{}, token)
	ctx = context.WithValue(ctx, dnsserver.Key{}, &dnsserver.Server{Addr: server})
	ctx = metadata.ContextWithMetadata(ctx)
	var meta map[string]string
	if metaJSON != "{}" {
		_ = json.Unmarshal([]byte(metaJSON), &meta)
	}
	for k, v := range meta {
		v := v
		metadata.SetValueFunc(ctx, k, func() string { return v })
	}
	w := &bridgeWriter{token: token, remote: addr(remote, proto), local: addr(local, proto)}
	rcode, err := in.handler.ServeDNS(ctx, w, m)
	done(token, rcode, err)
}

// bridgeWriter hands written responses to Rust.
type bridgeWriter struct {
	token         uint64
	remote, local net.Addr
}

func (w *bridgeWriter) LocalAddr() net.Addr      { return w.local }
func (w *bridgeWriter) RemoteAddr() net.Addr     { return w.remote }
func (w *bridgeWriter) Close() error             { return nil }
func (w *bridgeWriter) TsigStatus() error        { return nil }
func (w *bridgeWriter) TsigTimersOnly(bool)      {}
func (w *bridgeWriter) Hijack()                  {}
func (w *bridgeWriter) Write(b []byte) (int, error) {
	p, n := bytesPtr(b)
	C.kb_call_write(C.uint64_t(w.token), p, n)
	return len(b), nil
}

func (w *bridgeWriter) WriteMsg(m *dns.Msg) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// rustNext is the "next plugin" of every bridged chain: the rest of the
// KernDNS chain.
type rustNext struct{}

func (rustNext) Name() string { return "kerndns" }

func (rustNext) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	token, _ := ctx.Value(tokenKey{}).(uint64)
	b, err := r.Pack()
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	nt := nextToken.Add(1)
	ch := make(chan nextResult, 1)
	waits.Store(nt, ch)
	p, n := bytesPtr(b)
	C.kb_call_next(C.uint64_t(token), C.uint64_t(nt), p, n)
	res := <-ch
	for _, raw := range res.msgs {
		m := new(dns.Msg)
		if err := m.Unpack(raw); err != nil {
			return dns.RcodeServerFailure, err
		}
		if err := w.WriteMsg(m); err != nil {
			return dns.RcodeServerFailure, err
		}
	}
	if res.err != "" {
		return res.rcode, errors.New(res.err)
	}
	return res.rcode, nil
}

// kb_next_done answers a kb_call_next: the rcode, the messages the Rust
// chain wrote (each prefixed with a 2-byte length) and its error text.
//
//export kb_next_done
func kb_next_done(token C.uint64_t, rcode C.int, data *C.uint8_t, n C.size_t, errText *C.char) {
	v, ok := waits.LoadAndDelete(uint64(token))
	if !ok {
		return
	}
	buf := C.GoBytes(unsafe.Pointer(data), C.int(n))
	var msgs [][]byte
	for len(buf) >= 2 {
		l := int(binary.BigEndian.Uint16(buf))
		if len(buf) < 2+l {
			break
		}
		msgs = append(msgs, buf[2:2+l])
		buf = buf[2+l:]
	}
	v.(chan nextResult) <- nextResult{rcode: int(rcode), msgs: msgs, err: C.GoString(errText)}
}
