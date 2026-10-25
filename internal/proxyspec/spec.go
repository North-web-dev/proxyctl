// Package proxyspec parses proxy list entries into a normalized form.
package proxyspec

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Proxy is a single parsed upstream proxy.
type Proxy struct {
	Scheme string
	Host   string
	Port   string
	User   string
	Pass   string
	Raw    string
}

// Supported reports whether the scheme is one proxyctl knows how to speak.
func Supported(scheme string) bool {
	switch scheme {
	case "http", "https", "socks5", "socks5h":
		return true
	}
	return false
}

// HostPort returns host:port for dialing.
func (p Proxy) HostPort() string { return p.Host + ":" + p.Port }

// URL rebuilds a canonical scheme://[user:pass@]host:port string.
func (p Proxy) URL() *url.URL {
	u := &url.URL{Scheme: p.Scheme, Host: p.HostPort()}
	if p.User != "" || p.Pass != "" {
		u.User = url.UserPassword(p.User, p.Pass)
	}
	return u
}

// Label is a stable, credential-free identifier for display.
func (p Proxy) Label() string { return p.Scheme + "://" + p.HostPort() }

// redact removes any credentials from an entry so it is safe to put in an error
// or log string. It keeps scheme/host:port where it can, and never emits a
// password. Unparseable input collapses to a generic placeholder.
func redact(raw string) string {
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
		if i := strings.Index(raw, "://"); i >= 0 {
			return raw[:i] + "://<redacted>"
		}
		return "<redacted>"
	}
	parts := strings.Split(raw, ":")
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1] // host:port, drop any user:pass tail
	}
	return "<redacted>"
}

// Parse reads one entry. It accepts scheme://user:pass@host:port and the bare
// forms host:port and host:port:user:pass. Bare entries take defaultScheme.
func Parse(line, defaultScheme string) (Proxy, error) {
	raw := strings.TrimSpace(line)
	if raw == "" {
		return Proxy{}, fmt.Errorf("empty entry")
	}
	if strings.Contains(raw, "://") {
		return parseURL(raw)
	}
	return parseBare(raw, defaultScheme)
}

func parseURL(raw string) (Proxy, error) {
	safe := redact(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return Proxy{}, fmt.Errorf("invalid proxy URL %q", safe)
	}
	scheme := strings.ToLower(u.Scheme)
	if !Supported(scheme) {
		return Proxy{}, fmt.Errorf("unsupported scheme %q in %q", scheme, safe)
	}
	host, port := u.Hostname(), u.Port()
	if host == "" || port == "" {
		return Proxy{}, fmt.Errorf("missing host or port in %q", safe)
	}
	p := Proxy{Scheme: scheme, Host: host, Port: port, Raw: raw}
	if u.User != nil {
		p.User = u.User.Username()
		p.Pass, _ = u.User.Password()
	}
	return p, nil
}

func parseBare(raw, defaultScheme string) (Proxy, error) {
	if defaultScheme == "" {
		defaultScheme = "http"
	}
	if !Supported(defaultScheme) {
		return Proxy{}, fmt.Errorf("unsupported default scheme %q", defaultScheme)
	}
	safe := redact(raw)
	parts := strings.Split(raw, ":")
	switch len(parts) {
	case 2:
		if err := checkPort(parts[1]); err != nil {
			return Proxy{}, fmt.Errorf("%q: %w", safe, err)
		}
		return Proxy{Scheme: defaultScheme, Host: parts[0], Port: parts[1], Raw: raw}, nil
	case 4:
		if err := checkPort(parts[1]); err != nil {
			return Proxy{}, fmt.Errorf("%q: %w", safe, err)
		}
		return Proxy{Scheme: defaultScheme, Host: parts[0], Port: parts[1], User: parts[2], Pass: parts[3], Raw: raw}, nil
	default:
		return Proxy{}, fmt.Errorf("cannot parse bare entry %q (want host:port or host:port:user:pass)", safe)
	}
}

func checkPort(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", s)
	}
	return nil
}

// ParseList reads many entries, skipping blank lines and # comments. It returns
// the parsed proxies and a slice of per-line errors (never aborting the batch).
func ParseList(data, defaultScheme string) ([]Proxy, []error) {
	var out []Proxy
	var errs []error
	for _, ln := range strings.Split(data, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		p, err := Parse(t, defaultScheme)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, p)
	}
	return out, errs
}
