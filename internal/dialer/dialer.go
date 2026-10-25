// Package dialer tunnels TCP (and probes UDP) through a single upstream proxy.
//
// It speaks enough of HTTP CONNECT and SOCKS5 to establish a tunnel to an
// arbitrary target, plus a SOCKS5 UDP ASSOCIATE probe. It deliberately does not
// reuse connections: every call stands up a fresh tunnel so a check measures
// the proxy, not a cached socket.
package dialer

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/North-web-dev/proxyctl/internal/proxyspec"
)

// Dial opens a TCP tunnel through the proxy to target ("host:port"). resolveAt
// controls where a hostname is resolved for SOCKS5: "remote" sends the name to
// the proxy (socks5h), "local" resolves it here first (socks5). It is ignored
// for HTTP proxies, which always resolve at the proxy.
func Dial(ctx context.Context, p proxyspec.Proxy, target string, timeout time.Duration) (net.Conn, error) {
	switch p.Scheme {
	case "http", "https":
		return dialHTTP(ctx, p, target, timeout)
	case "socks5":
		return dialSOCKS5(ctx, p, target, timeout, "local")
	case "socks5h":
		return dialSOCKS5(ctx, p, target, timeout, "remote")
	default:
		return nil, fmt.Errorf("unsupported scheme %q", p.Scheme)
	}
}

// DialContextFunc returns a dialer suitable for http.Transport.DialContext. The
// network/addr come from the transport; the proxy and resolution mode are fixed.
func DialContextFunc(p proxyspec.Proxy, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		return Dial(ctx, p, addr, timeout)
	}
}

func baseDial(ctx context.Context, p proxyspec.Proxy, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", p.HostPort())
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	if p.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: p.Host})
		if err := tlsHandshake(ctx, tc, timeout); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls to proxy: %w", err)
		}
		return tc, nil
	}
	return conn, nil
}

func dialHTTP(ctx context.Context, p proxyspec.Proxy, target string, timeout time.Duration) (net.Conn, error) {
	conn, err := baseDial(ctx, p, timeout)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if p.User != "" || p.Pass != "" {
		fmt.Fprintf(&sb, "Proxy-Authorization: %s\r\n", basicAuth(p.User, p.Pass))
	}
	sb.WriteString("\r\n")
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT reply: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("CONNECT refused: %s", resp.Status)
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

// SOCKS5 reply codes per RFC 1928.
var socksReply = map[byte]string{
	0: "succeeded", 1: "general failure", 2: "not allowed", 3: "network unreachable",
	4: "host unreachable", 5: "connection refused", 6: "TTL expired",
	7: "command not supported", 8: "address type not supported",
}

func dialSOCKS5(ctx context.Context, p proxyspec.Proxy, target string, timeout time.Duration, resolveAt string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("bad target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("bad port %q: %w", portStr, err)
	}
	conn, err := baseDial(ctx, p, timeout)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	if err := socksHandshake(conn, p); err != nil {
		conn.Close()
		return nil, err
	}
	addr, err := socksAddr(host, port, resolveAt)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// VER=5 CMD=CONNECT(1) RSV=0
	reqBuf := append([]byte{5, 1, 0}, addr...)
	if _, err := conn.Write(reqBuf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	if _, _, err := readSocksReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func socksHandshake(conn net.Conn, p proxyspec.Proxy) error {
	authUserPass := p.User != "" || p.Pass != ""
	methods := []byte{0} // no-auth
	if authUserPass {
		methods = []byte{0, 2}
	}
	hello := append([]byte{5, byte(len(methods))}, methods...)
	if _, err := conn.Write(hello); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return fmt.Errorf("read method select: %w", err)
	}
	if sel[0] != 5 {
		return fmt.Errorf("not a SOCKS5 proxy (version %d)", sel[0])
	}
	switch sel[1] {
	case 0:
		return nil
	case 2:
		return socksUserPass(conn, p)
	case 0xff:
		return errors.New("proxy rejected all auth methods")
	default:
		return fmt.Errorf("proxy chose unsupported auth method %d", sel[1])
	}
}

func socksUserPass(conn net.Conn, p proxyspec.Proxy) error {
	if len(p.User) > 255 || len(p.Pass) > 255 {
		return errors.New("socks5 user/pass too long")
	}
	buf := []byte{1, byte(len(p.User))}
	buf = append(buf, p.User...)
	buf = append(buf, byte(len(p.Pass)))
	buf = append(buf, p.Pass...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("write auth: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("read auth reply: %w", err)
	}
	if resp[1] != 0 {
		return errors.New("socks5 authentication failed")
	}
	return nil
}

func socksAddr(host string, port int, resolveAt string) ([]byte, error) {
	var out []byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append([]byte{1}, v4...)
		} else {
			out = append([]byte{4}, ip.To16()...)
		}
	} else if resolveAt == "remote" {
		if len(host) > 255 {
			return nil, errors.New("hostname too long for socks5")
		}
		out = append([]byte{3, byte(len(host))}, host...)
	} else {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("local resolve %q: %w", host, err)
		}
		ip := ips[0]
		if v4 := ip.To4(); v4 != nil {
			out = append([]byte{1}, v4...)
		} else {
			out = append([]byte{4}, ip.To16()...)
		}
	}
	return binary.BigEndian.AppendUint16(out, uint16(port)), nil
}

// readSocksReply consumes a reply and returns the bound address it reports.
func readSocksReply(conn net.Conn) (net.IP, int, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, 0, fmt.Errorf("read reply: %w", err)
	}
	if head[1] != 0 {
		return nil, 0, fmt.Errorf("socks5: %s", socksReply[head[1]])
	}
	var ip net.IP
	switch head[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, 0, err
		}
		ip = net.IP(b)
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return nil, 0, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, 0, err
		}
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, 0, err
		}
		ip = net.IP(b)
	default:
		return nil, 0, fmt.Errorf("unknown atyp %d", head[3])
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return nil, 0, err
	}
	return ip, int(binary.BigEndian.Uint16(pb)), nil
}

// UDPResult reports a SOCKS5 UDP ASSOCIATE probe.
type UDPResult struct {
	Supported bool
	RelayAddr string
	Echoed    bool // a datagram sent to the relay produced a reply
	Detail    string
}

// ProbeUDP issues UDP ASSOCIATE and, if granted, sends one datagram to confirm
// the relay actually forwards. Only meaningful for socks5/socks5h.
func ProbeUDP(ctx context.Context, p proxyspec.Proxy, timeout time.Duration) (UDPResult, error) {
	if p.Scheme != "socks5" && p.Scheme != "socks5h" {
		return UDPResult{Detail: "not a socks5 proxy"}, nil
	}
	conn, err := baseDial(ctx, p, timeout)
	if err != nil {
		return UDPResult{}, err
	}
	defer conn.Close()
	if timeout > 0 {
		conn.SetDeadline(time.Now().Add(timeout))
	}
	if err := socksHandshake(conn, p); err != nil {
		return UDPResult{}, err
	}
	// CMD=UDP ASSOCIATE(3), client addr 0.0.0.0:0.
	req := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return UDPResult{}, fmt.Errorf("write ASSOCIATE: %w", err)
	}
	ip, port, err := readSocksReply(conn)
	if err != nil {
		return UDPResult{Supported: false, Detail: err.Error()}, nil
	}
	if ip == nil || ip.IsUnspecified() {
		ip = net.ParseIP(p.Host)
	}
	relay := net.JoinHostPort(ipString(ip, p.Host), strconv.Itoa(port))
	res := UDPResult{Supported: true, RelayAddr: relay, Detail: "ASSOCIATE granted"}
	res.Echoed = probeRelayDatagram(relay, timeout)
	if res.Echoed {
		res.Detail = "ASSOCIATE granted; relay forwarded a datagram"
	}
	return res, nil
}

// probeRelayDatagram sends a DNS query for example.com to 8.8.8.8 via the relay
// and waits for any reply. The caller keeps the TCP control connection open.
func probeRelayDatagram(relay string, timeout time.Duration) bool {
	raddr, err := net.ResolveUDPAddr("udp", relay)
	if err != nil {
		return false
	}
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return false
	}
	defer uc.Close()
	if timeout > 0 {
		uc.SetDeadline(time.Now().Add(timeout))
	}
	dns := dnsQuery("example.com")
	// SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) addr port, then payload.
	hdr := []byte{0, 0, 0, 1, 8, 8, 8, 8, 0, 53}
	if _, err := uc.Write(append(hdr, dns...)); err != nil {
		return false
	}
	buf := make([]byte, 1024)
	n, err := uc.Read(buf)
	return err == nil && n > 0
}

func dnsQuery(name string) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range splitDomain(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	return append(msg, 0, 0, 1, 0, 1)
}

func splitDomain(name string) []string {
	var out []string
	cur := ""
	for _, r := range name {
		if r == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func ipString(ip net.IP, fallback string) string {
	if ip != nil && !ip.IsUnspecified() {
		return ip.String()
	}
	return fallback
}

func tlsHandshake(ctx context.Context, tc *tls.Conn, timeout time.Duration) error {
	if timeout > 0 {
		tc.SetDeadline(time.Now().Add(timeout))
	}
	err := tc.HandshakeContext(ctx)
	tc.SetDeadline(time.Time{})
	return err
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}
