package checks

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/North-web-dev/proxyctl/internal/proxyspec"
	"github.com/North-web-dev/proxyctl/internal/testproxy"
)

func TestClassifyAnonymity(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		origin  string
		realIP  string
		want    string
	}{
		{"elite no headers", map[string]string{"User-Agent": "x"}, "9.9.9.9", "", Elite},
		{"anonymous via header", map[string]string{"Via": "1.1 squid"}, "9.9.9.9", "", Anonymous},
		{"anonymous xff real unknown", map[string]string{"X-Forwarded-For": "9.9.9.9"}, "9.9.9.9", "", Anonymous},
		{"transparent xff leaks real ip", map[string]string{"X-Forwarded-For": "5.5.5.5"}, "9.9.9.9", "5.5.5.5", Transparent},
		{"transparent origin is real ip", map[string]string{}, "5.5.5.5", "5.5.5.5", Transparent},
		{"elite real ip known but hidden", map[string]string{}, "9.9.9.9", "5.5.5.5", Elite},
		{"anonymous real ip known not leaked", map[string]string{"Via": "1.1 p"}, "9.9.9.9", "5.5.5.5", Anonymous},
		{"lowercase header name", map[string]string{"x-real-ip": "1.2.3.4"}, "9.9.9.9", "", Anonymous},
		{"empty header value ignored", map[string]string{"Via": ""}, "9.9.9.9", "", Elite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := classifyAnonymity(tt.headers, tt.origin, tt.realIP)
			if got != tt.want {
				t.Fatalf("classifyAnonymity = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMedian(t *testing.T) {
	cases := []struct {
		in   []int64
		want int64
	}{
		{nil, -1},
		{[]int64{5}, 5},
		{[]int64{3, 1, 2}, 2},
		{[]int64{4, 1, 3, 2}, 2},
	}
	for _, c := range cases {
		if got := median(c.in); got != c.want {
			t.Fatalf("median(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

// echoServer is an httpbin-compatible header echo.
func echoServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := map[string]string{}
		for k := range r.Header {
			headers[k] = r.Header.Get(k)
		}
		origin := r.Header.Get("X-Forwarded-For")
		if origin == "" {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			origin = host
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"origin": origin, "headers": headers})
	}))
}

func TestRunHTTPProxyElite(t *testing.T) {
	echo := echoServer()
	defer echo.Close()
	proxy, err := testproxy.StartHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	host, port, _ := net.SplitHostPort(mustURL(t, echo.URL).Host)
	p := proxyspec.Proxy{Scheme: "http", Host: hostOf(proxy.Addr()), Port: portOf(proxy.Addr())}
	opts := Options{EchoURL: echo.URL, Timeout: 5 * time.Second, Probes: 2,
		ConnectHost: net.JoinHostPort(host, port)}

	r := Run(context.Background(), p, opts)
	if !r.Live {
		t.Fatalf("expected live, err=%q", r.Error)
	}
	if r.Protocol != OK {
		t.Fatalf("protocol = %q", r.Protocol)
	}
	if r.LatencyMS < 0 {
		t.Fatalf("latency not measured")
	}
	if r.Connect != OK {
		t.Fatalf("connect = %q, want ok", r.Connect)
	}
	if r.Anonymity != Elite {
		t.Fatalf("anonymity = %q, want elite", r.Anonymity)
	}
	if r.DNS != "remote" {
		t.Fatalf("dns = %q", r.DNS)
	}
}

func TestRunHTTPProxyAnonymous(t *testing.T) {
	echo := echoServer()
	defer echo.Close()
	proxy, err := testproxy.StartHTTP()
	if err != nil {
		t.Fatal(err)
	}
	proxy.AddForwardFor = "203.0.113.7"
	defer proxy.Close()

	p := proxyspec.Proxy{Scheme: "http", Host: hostOf(proxy.Addr()), Port: portOf(proxy.Addr())}
	opts := Options{EchoURL: echo.URL, Timeout: 5 * time.Second, Probes: 1}
	r := Run(context.Background(), p, opts)
	if r.Anonymity != Anonymous {
		t.Fatalf("anonymity = %q, want anonymous", r.Anonymity)
	}
}

func TestRunSOCKS5WithUDP(t *testing.T) {
	echo := echoServer()
	defer echo.Close()
	s, err := testproxy.StartSOCKS5(true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	p := proxyspec.Proxy{Scheme: "socks5h", Host: hostOf(s.Addr()), Port: portOf(s.Addr())}
	opts := Options{EchoURL: echo.URL, Timeout: 5 * time.Second, Probes: 1}
	r := Run(context.Background(), p, opts)
	if !r.Live || r.Protocol != OK {
		t.Fatalf("socks5 not live: live=%v proto=%q err=%q", r.Live, r.Protocol, r.Error)
	}
	if r.UDP != OK {
		t.Fatalf("udp = %q, want ok (%s)", r.UDP, r.UDPDetail)
	}
	if r.DNS != "remote" {
		t.Fatalf("dns = %q, want remote for socks5h", r.DNS)
	}
}

func TestRunSOCKS5NoUDP(t *testing.T) {
	echo := echoServer()
	defer echo.Close()
	s, err := testproxy.StartSOCKS5(false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	p := proxyspec.Proxy{Scheme: "socks5", Host: hostOf(s.Addr()), Port: portOf(s.Addr())}
	opts := Options{EchoURL: echo.URL, Timeout: 5 * time.Second, Probes: 1}
	r := Run(context.Background(), p, opts)
	if r.UDP != Fail {
		t.Fatalf("udp = %q, want fail for a TCP-only proxy", r.UDP)
	}
	if r.DNS != "local" {
		t.Fatalf("dns = %q, want local for socks5", r.DNS)
	}
}

func TestRunDeadProxy(t *testing.T) {
	echo := echoServer()
	defer echo.Close()
	p := proxyspec.Proxy{Scheme: "http", Host: "127.0.0.1", Port: "1"}
	opts := Options{EchoURL: echo.URL, Timeout: 500 * time.Millisecond, Probes: 1}
	r := Run(context.Background(), p, opts)
	if r.Live {
		t.Fatalf("expected dead proxy")
	}
	if r.Error == "" {
		t.Fatalf("expected an error message on a dead proxy")
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func hostOf(hp string) string { h, _, _ := net.SplitHostPort(hp); return h }
func portOf(hp string) string { _, p, _ := net.SplitHostPort(hp); return p }
