// Package testproxy provides in-process mock proxies for tests: a combined
// HTTP CONNECT + forward proxy and a SOCKS5 server with optional UDP ASSOCIATE.
// It stands up real listeners so the dialer exercises real wire protocols,
// without depending on any external proxy.
package testproxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// HTTP is a mock HTTP proxy supporting CONNECT tunnels and absolute-form GET
// forwarding. AddForwardFor, if set, is injected as X-Forwarded-For on
// forwarded (non-CONNECT) requests so anonymity paths can be exercised.
type HTTP struct {
	ln            net.Listener
	AddForwardFor string
	wg            sync.WaitGroup
}

// StartHTTP starts a mock HTTP proxy on a random loopback port.
func StartHTTP() (*HTTP, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	h := &HTTP{ln: ln}
	go h.serve()
	return h, nil
}

// Addr returns host:port.
func (h *HTTP) Addr() string { return h.ln.Addr().String() }

// Close stops the proxy.
func (h *HTTP) Close() { h.ln.Close(); h.wg.Wait() }

func (h *HTTP) serve() {
	for {
		c, err := h.ln.Accept()
		if err != nil {
			return
		}
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			h.handle(c)
		}()
	}
}

func (h *HTTP) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		up, err := net.Dial("tcp", req.Host)
		if err != nil {
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer up.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		pipe(c, up)
		return
	}
	if !req.URL.IsAbs() {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	up, err := net.Dial("tcp", host)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer up.Close()
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	fmt.Fprintf(&sb, "Host: %s\r\n", req.URL.Host)
	if h.AddForwardFor != "" {
		fmt.Fprintf(&sb, "X-Forwarded-For: %s\r\n", h.AddForwardFor)
		sb.WriteString("Via: 1.1 testproxy\r\n")
	}
	for k, vs := range req.Header {
		if strings.HasPrefix(k, "Proxy-") {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	sb.WriteString("Connection: close\r\n\r\n")
	io.WriteString(up, sb.String())
	io.Copy(c, up)
}

// SOCKS5 is a mock SOCKS5 proxy. If UDP is true it honors UDP ASSOCIATE and
// echoes datagrams back; otherwise it refuses ASSOCIATE (TCP-only).
type SOCKS5 struct {
	ln   net.Listener
	UDP  bool
	Auth bool // require username/password
	User string
	Pass string
	wg   sync.WaitGroup
}

// StartSOCKS5 starts a mock SOCKS5 proxy on a random loopback port.
func StartSOCKS5(udp bool) (*SOCKS5, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &SOCKS5{ln: ln, UDP: udp}
	go s.serve()
	return s, nil
}

func (s *SOCKS5) Addr() string { return s.ln.Addr().String() }
func (s *SOCKS5) Close()       { s.ln.Close(); s.wg.Wait() }

func (s *SOCKS5) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

func (s *SOCKS5) handle(c net.Conn) {
	defer c.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if s.Auth {
		c.Write([]byte{5, 2})
		if !s.doAuth(c) {
			return
		}
	} else {
		c.Write([]byte{5, 0})
	}
	reqHead := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHead); err != nil || reqHead[0] != 5 {
		return
	}
	host, port, err := readAddr(c, reqHead[3])
	if err != nil {
		return
	}
	switch reqHead[1] {
	case 1:
		s.doConnect(c, host, port)
	case 3:
		s.doUDP(c)
	default:
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func (s *SOCKS5) doAuth(c net.Conn) bool {
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil || h[0] != 1 {
		return false
	}
	user := make([]byte, int(h[1]))
	io.ReadFull(c, user)
	pl := make([]byte, 1)
	io.ReadFull(c, pl)
	pass := make([]byte, int(pl[0]))
	io.ReadFull(c, pass)
	if string(user) == s.User && string(pass) == s.Pass {
		c.Write([]byte{1, 0})
		return true
	}
	c.Write([]byte{1, 1})
	return false
}

func (s *SOCKS5) doConnect(c net.Conn, host string, port int) {
	up, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	pipe(c, up)
}

func (s *SOCKS5) doUDP(c net.Conn) {
	if !s.UDP {
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer uc.Close()
	local := uc.LocalAddr().(*net.UDPAddr)
	reply := []byte{5, 0, 0, 1}
	reply = append(reply, local.IP.To4()...)
	reply = binary.BigEndian.AppendUint16(reply, uint16(local.Port))
	c.Write(reply)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			uc.WriteToUDP(buf[:n], from) // echo the whole datagram, header included
		}
	}()
	io.ReadFull(c, make([]byte, 1)) // block until client closes the control conn
}

func readAddr(c net.Conn, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	default:
		return "", 0, fmt.Errorf("bad atyp")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(pb)), nil
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) { io.Copy(dst, src); done <- struct{}{} }
	go cp(a, b)
	go cp(b, a)
	<-done
}
