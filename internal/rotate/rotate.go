// Package rotate runs a local forward proxy that cycles healthy upstream
// proxies. It is a simple rotator, not a full proxy server: one upstream is
// chosen per client request, dead upstreams are ejected, and a background loop
// revives them. HTTP and HTTPS (via CONNECT) clients are supported.
package rotate

import (
	"bufio"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/North-web-dev/proxyctl/internal/dialer"
	"github.com/North-web-dev/proxyctl/internal/proxyspec"
)

// Strategy selects the next upstream.
type Strategy string

const (
	RoundRobin   Strategy = "round-robin"
	Random       Strategy = "random"
	LeastLatency Strategy = "least-latency"
)

// Upstream is one proxy in the rotation with live health state.
type Upstream struct {
	Proxy proxyspec.Proxy

	mu        sync.Mutex
	healthy   bool
	latencyMS int64
	fails     int
}

func (u *Upstream) snapshot() (bool, int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.healthy, u.latencyMS
}

// Pool holds the rotation set and its selection policy.
type Pool struct {
	ups       []*Upstream
	strategy  Strategy
	probeHost string
	timeout   time.Duration
	failLimit int
	rr        uint64
	rnd       *rand.Rand
	rndMu     sync.Mutex
}

// NewPool builds a pool. probeHost is the host:port used for health checks.
func NewPool(proxies []proxyspec.Proxy, strategy Strategy, probeHost string, timeout time.Duration) *Pool {
	ups := make([]*Upstream, len(proxies))
	for i, p := range proxies {
		ups[i] = &Upstream{Proxy: p, latencyMS: -1}
	}
	if probeHost == "" {
		probeHost = "example.com:443"
	}
	return &Pool{
		ups:       ups,
		strategy:  strategy,
		probeHost: probeHost,
		timeout:   timeout,
		failLimit: 3,
		rnd:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (p *Pool) healthySlice() []*Upstream {
	var out []*Upstream
	for _, u := range p.ups {
		if h, _ := u.snapshot(); h {
			out = append(out, u)
		}
	}
	return out
}

// Next returns the next healthy upstream per the strategy, or nil if none.
func (p *Pool) Next() *Upstream {
	healthy := p.healthySlice()
	if len(healthy) == 0 {
		return nil
	}
	switch p.strategy {
	case Random:
		p.rndMu.Lock()
		u := healthy[p.rnd.Intn(len(healthy))]
		p.rndMu.Unlock()
		return u
	case LeastLatency:
		sort.SliceStable(healthy, func(i, j int) bool {
			_, li := healthy[i].snapshot()
			_, lj := healthy[j].snapshot()
			if li < 0 {
				return false
			}
			if lj < 0 {
				return true
			}
			return li < lj
		})
		return healthy[0]
	default:
		n := atomic.AddUint64(&p.rr, 1)
		return healthy[int(n-1)%len(healthy)]
	}
}

// reportFailure ejects an upstream after failLimit consecutive failures.
func (p *Pool) reportFailure(u *Upstream) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.fails++
	if u.fails >= p.failLimit {
		u.healthy = false
	}
}

func (p *Pool) setHealth(u *Upstream, healthy bool, latencyMS int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.healthy = healthy
	u.latencyMS = latencyMS
	if healthy {
		u.fails = 0
	}
}

// HealthCheck probes every upstream once and updates its state.
func (p *Pool) HealthCheck(ctx context.Context) {
	var wg sync.WaitGroup
	for _, u := range p.ups {
		wg.Add(1)
		go func(u *Upstream) {
			defer wg.Done()
			start := time.Now()
			conn, err := dialer.Dial(ctx, u.Proxy, p.probeHost, p.timeout)
			if err != nil {
				p.setHealth(u, false, -1)
				return
			}
			conn.Close()
			p.setHealth(u, true, time.Since(start).Milliseconds())
		}(u)
	}
	wg.Wait()
}

// Run starts a background health loop until ctx is cancelled.
func (p *Pool) Run(ctx context.Context, interval time.Duration) {
	p.HealthCheck(ctx)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.HealthCheck(ctx)
			}
		}
	}()
}

// Stats is a point-in-time view of the pool.
type Stats struct {
	Total   int
	Healthy int
	Entries []EntryStat
}

// EntryStat is one upstream's visible state.
type EntryStat struct {
	Label     string
	Healthy   bool
	LatencyMS int64
}

// Stats returns the current pool state.
func (p *Pool) Stats() Stats {
	s := Stats{Total: len(p.ups)}
	for _, u := range p.ups {
		h, l := u.snapshot()
		if h {
			s.Healthy++
		}
		s.Entries = append(s.Entries, EntryStat{Label: u.Proxy.Label(), Healthy: h, LatencyMS: l})
	}
	return s
}

// Server is the rotating forward proxy.
type Server struct {
	Pool    *Pool
	Timeout time.Duration
	// Auth, if set, is the exact Proxy-Authorization value a client must send
	// (e.g. "Basic <base64(user:pass)>"). Empty means no client auth.
	Auth string
	Log  func(string, ...any)
}

func (s *Server) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log(format, a...)
	}
}

func (s *Server) authOK(r *http.Request) bool {
	if s.Auth == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte(s.Auth)) == 1
}

// ServeHTTP implements the forward proxy for HTTP and CONNECT.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.authOK(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxyctl"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	u := s.Pool.Next()
	if u == nil {
		http.Error(w, "no healthy upstream", http.StatusServiceUnavailable)
		return
	}
	target, err := dialer.Dial(r.Context(), u.Proxy, r.Host, s.Timeout)
	if err != nil {
		s.Pool.reportFailure(u)
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	defer target.Close()
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	defer client.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	s.logf("CONNECT %s via %s", r.Host, u.Proxy.Label())
	pipe(client, target)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "this is a forward proxy; use an absolute-form request URI", http.StatusBadRequest)
		return
	}
	u := s.Pool.Next()
	if u == nil {
		http.Error(w, "no healthy upstream", http.StatusServiceUnavailable)
		return
	}
	target := canonicalAddr(r.URL)
	conn, err := dialer.Dial(r.Context(), u.Proxy, target, s.Timeout)
	if err != nil {
		s.Pool.reportFailure(u)
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	defer conn.Close()
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	stripHopByHop(outReq.Header)
	if s.Timeout > 0 {
		conn.SetDeadline(time.Now().Add(s.Timeout))
	}
	if err := outReq.Write(conn); err != nil {
		s.Pool.reportFailure(u)
		http.Error(w, "write upstream request failed", http.StatusBadGateway)
		return
	}
	s.logf("%s %s via %s", r.Method, r.URL, u.Proxy.Label())
	resp, err := http.ReadResponse(bufio.NewReader(conn), outReq)
	if err != nil {
		s.Pool.reportFailure(u)
		http.Error(w, "read upstream response failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	stripHopByHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func canonicalAddr(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripHopByHop(h http.Header) {
	for _, k := range hopByHop {
		h.Del(k)
	}
}

// IsLoopbackAddr reports whether a listen address binds only to loopback. A
// missing or empty host (e.g. ":8080") binds all interfaces and is not
// loopback. Unresolvable hosts are treated as non-loopback (fail safe).
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}

func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{Addr: addr, Handler: s}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	return srv.Serve(ln)
}
