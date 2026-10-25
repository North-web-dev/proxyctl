package dialer

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/North-web-dev/proxyctl/internal/proxyspec"
	"github.com/North-web-dev/proxyctl/internal/testproxy"
)

// rawEcho is a TCP server that echoes what it receives.
func rawEcho(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln
}

func hostOf(hp string) string { h, _, _ := net.SplitHostPort(hp); return h }
func portOf(hp string) string { _, p, _ := net.SplitHostPort(hp); return p }

func TestHTTPConnectTunnel(t *testing.T) {
	echo := rawEcho(t)
	defer echo.Close()
	proxy, err := testproxy.StartHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	p := proxyspec.Proxy{Scheme: "http", Host: hostOf(proxy.Addr()), Port: portOf(proxy.Addr())}
	conn, err := Dial(context.Background(), p, echo.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}

func TestSOCKS5ConnectWithAuth(t *testing.T) {
	echo := rawEcho(t)
	defer echo.Close()
	s, err := testproxy.StartSOCKS5(false)
	if err != nil {
		t.Fatal(err)
	}
	s.Auth, s.User, s.Pass = true, "bob", "secret"
	defer s.Close()

	p := proxyspec.Proxy{Scheme: "socks5", Host: hostOf(s.Addr()), Port: portOf(s.Addr()), User: "bob", Pass: "secret"}
	conn, err := Dial(context.Background(), p, echo.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial with auth: %v", err)
	}
	defer conn.Close()
	assertEcho(t, conn)
}

func TestSOCKS5AuthFailure(t *testing.T) {
	s, err := testproxy.StartSOCKS5(false)
	if err != nil {
		t.Fatal(err)
	}
	s.Auth, s.User, s.Pass = true, "bob", "secret"
	defer s.Close()

	p := proxyspec.Proxy{Scheme: "socks5", Host: hostOf(s.Addr()), Port: portOf(s.Addr()), User: "bob", Pass: "wrong"}
	if _, err := Dial(context.Background(), p, "example.com:443", 3*time.Second); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestProbeUDPSupported(t *testing.T) {
	s, err := testproxy.StartSOCKS5(true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := proxyspec.Proxy{Scheme: "socks5", Host: hostOf(s.Addr()), Port: portOf(s.Addr())}
	res, err := ProbeUDP(context.Background(), p, 3*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !res.Supported {
		t.Fatalf("expected UDP supported, got %+v", res)
	}
	if !res.Echoed {
		t.Fatalf("expected relay to echo a datagram, got %+v", res)
	}
}

func TestProbeUDPUnsupported(t *testing.T) {
	s, err := testproxy.StartSOCKS5(false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := proxyspec.Proxy{Scheme: "socks5", Host: hostOf(s.Addr()), Port: portOf(s.Addr())}
	res, err := ProbeUDP(context.Background(), p, 3*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Supported {
		t.Fatalf("expected UDP unsupported for TCP-only proxy, got %+v", res)
	}
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	msg := []byte("ping")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", string(buf))
	}
}
