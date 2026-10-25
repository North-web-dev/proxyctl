// Package checks runs the deep per-proxy probes and records honest results.
package checks

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/North-web-dev/proxyctl/internal/dialer"
	"github.com/North-web-dev/proxyctl/internal/proxyspec"
)

// Status values for an individual check.
const (
	OK   = "ok"
	Fail = "fail"
	NA   = "n/a"
	Skip = "skip"
)

// Anonymity levels.
const (
	Elite       = "elite"
	Anonymous   = "anonymous"
	Transparent = "transparent"
	Unknown     = "unknown"
)

// Options configures a run.
type Options struct {
	EchoURL      string
	Timeout      time.Duration
	Probes       int
	ConnectHost  string // host:port for the raw CONNECT/tunnel test
	SNIBenign    string // host:port, optional
	SNISensitive string // host:port, optional
	GeoURL       string // optional; {ip} substituted
	DetectRealIP bool   // make one direct (unproxied) echo request to learn egress IP
}

// Result is the full outcome for one proxy.
type Result struct {
	Proxy     string  `json:"proxy"`
	Scheme    string  `json:"scheme"`
	Live      bool    `json:"live"`
	LatencyMS int64   `json:"latency_ms"` // median; -1 if unknown
	Samples   []int64 `json:"samples_ms"` // per-probe latencies that succeeded
	Protocol  string  `json:"protocol"`   // ok/fail
	Connect   string  `json:"connect"`    // ok/fail/n/a
	Anonymity string  `json:"anonymity"`  // elite/anonymous/transparent/unknown
	ExitIP    string  `json:"exit_ip"`    // as seen by the echo; "" if unknown
	UDP       string  `json:"udp"`        // ok/fail/n/a
	UDPDetail string  `json:"udp_detail,omitempty"`
	DNS       string  `json:"dns"` // local/remote/n/a
	SNI       string  `json:"sni"` // verdict or "not checked"
	Geo       string  `json:"geo"` // info or "not checked"
	Score     int     `json:"score"`
	Error     string  `json:"error,omitempty"`
}

type echoResponse struct {
	Origin  string            `json:"origin"`
	Headers map[string]string `json:"headers"`
}

// forwardingHeaders are the header names whose presence means the proxy is
// announcing itself and/or forwarding client information.
var forwardingHeaders = []string{
	"Via", "X-Forwarded-For", "X-Forwarded", "Forwarded", "X-Real-Ip",
	"Client-Ip", "X-Client-Ip", "Proxy-Connection", "X-Proxy-Id",
}

// classifyAnonymity decides the level from the headers the echo reports seeing,
// the exit IP it reported (origin), and our real egress IP (may be ""). It is
// pure so it can be table-tested.
func classifyAnonymity(headers map[string]string, origin, realIP string) (string, string) {
	norm := map[string]string{}
	for k, v := range headers {
		norm[http.CanonicalHeaderKey(k)] = v
	}
	var present []string
	for _, h := range forwardingHeaders {
		if v, ok := norm[http.CanonicalHeaderKey(h)]; ok && strings.TrimSpace(v) != "" {
			present = append(present, h)
		}
	}
	if realIP != "" {
		leaked := strings.Contains(origin, realIP)
		for _, h := range present {
			if strings.Contains(norm[http.CanonicalHeaderKey(h)], realIP) {
				leaked = true
			}
		}
		if leaked {
			return Transparent, "real IP visible to the echo"
		}
	}
	if len(present) > 0 {
		detail := "forwarding headers present: " + strings.Join(present, ", ")
		if realIP == "" {
			detail += " (real IP unknown; could be transparent)"
		}
		return Anonymous, detail
	}
	return Elite, "no forwarding headers observed"
}

// Run executes the selected probes for one proxy.
func Run(ctx context.Context, p proxyspec.Proxy, o Options) Result {
	r := Result{Proxy: p.Label(), Scheme: p.Scheme, LatencyMS: -1, Protocol: Fail,
		Connect: NA, Anonymity: Unknown, UDP: NA, DNS: NA, SNI: "not checked", Geo: "not checked"}

	realIP := ""
	if o.DetectRealIP {
		realIP = directEgressIP(ctx, o.EchoURL, o.Timeout)
	}

	echo, samples := probeLatency(ctx, p, o)
	r.Samples = samples
	if len(samples) > 0 {
		r.Live = true
		r.Protocol = OK
		r.LatencyMS = median(samples)
	}
	if echo != nil {
		r.ExitIP = sanitize(echo.Origin)
		level, _ := classifyAnonymity(echo.Headers, echo.Origin, realIP)
		r.Anonymity = level
	}

	r.DNS = dnsMode(p.Scheme)
	r.Connect = connectCheck(ctx, p, o)
	r.UDP, r.UDPDetail = udpCheck(ctx, p, o)
	r.SNI = sniCheck(ctx, p, o)
	r.Geo = geoCheck(ctx, o, r.ExitIP)

	if !r.Live && r.Error == "" {
		r.Error = "no probe reached the echo through this proxy"
	}
	return r
}

func echoClient(p proxyspec.Proxy, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
	}
	switch p.Scheme {
	case "http", "https":
		tr.Proxy = http.ProxyURL(p.URL())
	default:
		tr.DialContext = dialer.DialContextFunc(p, timeout)
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func probeLatency(ctx context.Context, p proxyspec.Proxy, o Options) (*echoResponse, []int64) {
	client := echoClient(p, o.Timeout)
	defer client.CloseIdleConnections()
	var samples []int64
	var last *echoResponse
	n := o.Probes
	if n < 1 {
		n = 1
	}
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		resp, body, err := doGet(ctx, client, o.EchoURL)
		if err != nil {
			continue
		}
		samples = append(samples, time.Since(start).Milliseconds())
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			var er echoResponse
			if json.Unmarshal(body, &er) == nil {
				last = &er
			}
		}
	}
	return last, samples
}

func doGet(ctx context.Context, c *http.Client, url string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, body, nil
}

func directEgressIP(ctx context.Context, echoURL string, timeout time.Duration) string {
	c := &http.Client{Timeout: timeout}
	_, body, err := doGet(ctx, c, echoURL)
	if err != nil {
		return ""
	}
	var er echoResponse
	if json.Unmarshal(body, &er) == nil {
		return strings.TrimSpace(er.Origin)
	}
	return ""
}

func connectCheck(ctx context.Context, p proxyspec.Proxy, o Options) string {
	host := o.ConnectHost
	if host == "" {
		host = "example.com:443"
	}
	conn, err := dialer.Dial(ctx, p, host, o.Timeout)
	if err != nil {
		return Fail
	}
	conn.Close()
	return OK
}

func udpCheck(ctx context.Context, p proxyspec.Proxy, o Options) (string, string) {
	if p.Scheme != "socks5" && p.Scheme != "socks5h" {
		return NA, ""
	}
	res, err := dialer.ProbeUDP(ctx, p, o.Timeout)
	if err != nil {
		return Fail, err.Error()
	}
	if res.Supported {
		return OK, res.Detail
	}
	return Fail, res.Detail
}

func dnsMode(scheme string) string {
	switch scheme {
	case "socks5":
		return "local"
	case "socks5h":
		return "remote"
	case "http", "https":
		return "remote"
	}
	return NA
}

// sniCheck tunnels to the benign and sensitive hosts and compares TLS outcomes.
func sniCheck(ctx context.Context, p proxyspec.Proxy, o Options) string {
	if o.SNIBenign == "" || o.SNISensitive == "" {
		return "not checked"
	}
	benignErr := tlsThrough(ctx, p, o.SNIBenign, o.Timeout)
	sensErr := tlsThrough(ctx, p, o.SNISensitive, o.Timeout)
	switch {
	case benignErr == nil && sensErr == nil:
		return "no filtering (both reachable)"
	case benignErr == nil && sensErr != nil:
		return fmt.Sprintf("possible SNI filtering: %s ok, %s blocked (%s)",
			hostOnly(o.SNIBenign), hostOnly(o.SNISensitive), short(sensErr))
	case benignErr != nil && sensErr == nil:
		return fmt.Sprintf("inconclusive: benign %s failed (%s) but sensitive ok",
			hostOnly(o.SNIBenign), short(benignErr))
	default:
		return fmt.Sprintf("inconclusive: both failed (benign: %s)", short(benignErr))
	}
}

func geoCheck(ctx context.Context, o Options, exitIP string) string {
	if o.GeoURL == "" {
		return "not checked"
	}
	ip := net.ParseIP(exitIP)
	if ip == nil {
		return "not checked (no valid exit IP)"
	}
	target := strings.ReplaceAll(o.GeoURL, "{ip}", url.PathEscape(ip.String()))
	c := &http.Client{Timeout: o.Timeout}
	_, body, err := doGet(ctx, c, target)
	if err != nil {
		return "not checked (geo endpoint error: " + sanitize(short(err)) + ")"
	}
	return sanitize(string(body))
}

// sanitize strips CR/LF and non-printable characters from any echo- or
// geo-derived string before it is printed or placed in JSON, and caps length.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

// tlsThrough tunnels to hostPort and completes a TLS handshake using the host
// as SNI. A reset/blocked SNI surfaces here as a handshake error.
func tlsThrough(ctx context.Context, p proxyspec.Proxy, hostPort string, timeout time.Duration) error {
	conn, err := dialer.Dial(ctx, p, hostPort, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	tc := tls.Client(conn, &tls.Config{ServerName: hostOnly(hostPort)})
	return tc.HandshakeContext(ctx)
}

func median(v []int64) int64 {
	if len(v) == 0 {
		return -1
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func hostOnly(hp string) string {
	if h, _, err := net.SplitHostPort(hp); err == nil {
		return h
	}
	return hp
}

func short(err error) string {
	s := err.Error()
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
