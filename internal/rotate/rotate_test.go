package rotate

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/North-web-dev/proxyctl/internal/proxyspec"
	"github.com/North-web-dev/proxyctl/internal/testproxy"
)

func dummyPool(n int, strategy Strategy) *Pool {
	ps := make([]proxyspec.Proxy, n)
	for i := range ps {
		ps[i] = proxyspec.Proxy{Scheme: "http", Host: "10.0.0." + string(rune('1'+i)), Port: "8080"}
	}
	return NewPool(ps, strategy, "example.com:443", time.Second)
}

func TestNextEmptyWhenNoneHealthy(t *testing.T) {
	p := dummyPool(3, RoundRobin)
	if got := p.Next(); got != nil {
		t.Fatalf("expected nil with no healthy upstreams, got %v", got.Proxy.Label())
	}
}

func TestRoundRobinCyclesHealthy(t *testing.T) {
	p := dummyPool(3, RoundRobin)
	for _, u := range p.ups {
		p.setHealth(u, true, 10)
	}
	counts := map[string]int{}
	for i := 0; i < 6; i++ {
		counts[p.Next().Proxy.Label()]++
	}
	if len(counts) != 3 {
		t.Fatalf("expected all 3 used, got %v", counts)
	}
	for k, c := range counts {
		if c != 2 {
			t.Fatalf("expected even cycling, %s got %d", k, c)
		}
	}
}

func TestRoundRobinSkipsDead(t *testing.T) {
	p := dummyPool(3, RoundRobin)
	for _, u := range p.ups {
		p.setHealth(u, true, 10)
	}
	p.setHealth(p.ups[1], false, -1)
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		seen[p.Next().Proxy.Label()] = true
	}
	if seen[p.ups[1].Proxy.Label()] {
		t.Fatalf("dead upstream should never be returned")
	}
	if len(seen) != 2 {
		t.Fatalf("expected exactly 2 live upstreams in rotation, got %d", len(seen))
	}
}

func TestEjectAfterFailLimit(t *testing.T) {
	p := dummyPool(1, RoundRobin)
	p.setHealth(p.ups[0], true, 10)
	for i := 0; i < p.failLimit; i++ {
		if p.Next() == nil {
			t.Fatalf("upstream ejected too early at %d", i)
		}
		p.reportFailure(p.ups[0])
	}
	if p.Next() != nil {
		t.Fatalf("upstream should be ejected after %d failures", p.failLimit)
	}
}

func TestLeastLatencyPicksFastest(t *testing.T) {
	p := dummyPool(3, LeastLatency)
	p.setHealth(p.ups[0], true, 200)
	p.setHealth(p.ups[1], true, 50)
	p.setHealth(p.ups[2], true, 120)
	for i := 0; i < 5; i++ {
		if got := p.Next().Proxy.Label(); got != p.ups[1].Proxy.Label() {
			t.Fatalf("least-latency picked %s, want the 50ms upstream", got)
		}
	}
}

func TestHealthCheckAndForward(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello-from-target")
	}))
	defer target.Close()

	upstream, err := testproxy.StartHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	tHost, tPort, _ := net.SplitHostPort(mustHost(t, target.URL))
	up := proxyspec.Proxy{Scheme: "http", Host: hostOf(upstream.Addr()), Port: portOf(upstream.Addr())}
	pool := NewPool([]proxyspec.Proxy{up}, RoundRobin, net.JoinHostPort(tHost, tPort), 5*time.Second)
	pool.HealthCheck(context.Background())
	if pool.Stats().Healthy != 1 {
		t.Fatalf("health check should have marked the upstream healthy: %+v", pool.Stats())
	}

	srv := &Server{Pool: pool, Timeout: 5 * time.Second}
	rotator := httptest.NewServer(srv)
	defer rotator.Close()

	proxyURL, _ := url.Parse(rotator.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("request through rotator failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-from-target" {
		t.Fatalf("got %q through rotator", string(body))
	}
}

func TestForwardNoHealthyReturns503(t *testing.T) {
	pool := dummyPool(1, RoundRobin) // never health-checked => unhealthy
	srv := &Server{Pool: pool, Timeout: time.Second}
	rotator := httptest.NewServer(srv)
	defer rotator.Close()

	proxyURL, _ := url.Parse(rotator.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 3 * time.Second}
	resp, err := client.Get("http://example.invalid/")
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080": true,
		"localhost:8080": true,
		"[::1]:8080":     true,
		":8080":          false,
		"0.0.0.0:8080":   false,
		"192.168.1.5:80": false,
		"garbage":        false,
	}
	for in, want := range cases {
		if got := IsLoopbackAddr(in); got != want {
			t.Fatalf("IsLoopbackAddr(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestClientAuthEnforced(t *testing.T) {
	pool := dummyPool(1, RoundRobin)
	pool.setHealth(pool.ups[0], true, 10)
	srv := &Server{Pool: pool, Timeout: time.Second, Auth: "Basic dXNlcjpwYXNz"} // user:pass
	rotator := httptest.NewServer(srv)
	defer rotator.Close()

	proxyURL, _ := url.Parse(rotator.URL)

	noAuth := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 3 * time.Second}
	resp, err := noAuth.Get("http://example.invalid/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("without credentials status = %d, want 407", resp.StatusCode)
	}

	authURL, _ := url.Parse("http://user:pass@" + proxyURL.Host)
	withAuth := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(authURL)}, Timeout: 3 * time.Second}
	resp2, err := withAuth.Get("http://example.invalid/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp2.Body.Close()
	// Auth passes, so it proceeds to upstream selection (502, not 407).
	if resp2.StatusCode == http.StatusProxyAuthRequired {
		t.Fatalf("valid credentials still rejected with 407")
	}
}

func mustHost(t *testing.T, s string) string {
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func hostOf(hp string) string { h, _, _ := net.SplitHostPort(hp); return h }
func portOf(hp string) string { _, p, _ := net.SplitHostPort(hp); return p }
