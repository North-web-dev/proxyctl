package proxyspec

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		def     string
		want    Proxy
		wantErr bool
	}{
		{"scheme full", "socks5://bob:secret@1.2.3.4:1080", "http",
			Proxy{Scheme: "socks5", Host: "1.2.3.4", Port: "1080", User: "bob", Pass: "secret"}, false},
		{"scheme no auth", "http://10.0.0.1:3128", "http",
			Proxy{Scheme: "http", Host: "10.0.0.1", Port: "3128"}, false},
		{"https scheme", "https://proxy.example:8443", "http",
			Proxy{Scheme: "https", Host: "proxy.example", Port: "8443"}, false},
		{"socks5h scheme", "socks5h://h:9050", "http",
			Proxy{Scheme: "socks5h", Host: "h", Port: "9050"}, false},
		{"bare host port", "5.6.7.8:8080", "http",
			Proxy{Scheme: "http", Host: "5.6.7.8", Port: "8080"}, false},
		{"bare host port default socks5", "5.6.7.8:1080", "socks5",
			Proxy{Scheme: "socks5", Host: "5.6.7.8", Port: "1080"}, false},
		{"bare with auth", "5.6.7.8:8080:alice:pw", "http",
			Proxy{Scheme: "http", Host: "5.6.7.8", Port: "8080", User: "alice", Pass: "pw"}, false},
		{"unsupported scheme", "ftp://a:1", "http", Proxy{}, true},
		{"bad port", "host:99999", "http", Proxy{}, true},
		{"bare bad shape", "a:b:c", "http", Proxy{}, true},
		{"empty", "   ", "http", Proxy{}, true},
		{"bad default scheme", "host:80", "gopher", Proxy{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in, tt.def)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got.Raw = ""
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseList(t *testing.T) {
	data := "# a comment\n\nhttp://1.1.1.1:8080\nbadport:99999\nsocks5://2.2.2.2:1080\n   \n"
	got, errs := ParseList(data, "http")
	if len(got) != 2 {
		t.Fatalf("want 2 proxies, got %d", len(got))
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 error, got %d: %v", len(errs), errs)
	}
	if got[0].Label() != "http://1.1.1.1:8080" || got[1].Label() != "socks5://2.2.2.2:1080" {
		t.Fatalf("unexpected labels: %q %q", got[0].Label(), got[1].Label())
	}
}

func TestErrorsRedactCredentials(t *testing.T) {
	cases := []string{
		"socks5://user:SECRETPW@host:notaport",
		"gopher://user:SECRETPW@host:1080",
		"1.2.3.4:badport:user:SECRETPW",
	}
	for _, in := range cases {
		_, err := Parse(in, "http")
		if err == nil {
			t.Fatalf("%q: expected error", in)
		}
		if strings.Contains(err.Error(), "SECRETPW") {
			t.Fatalf("%q: error leaked password: %v", in, err)
		}
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"socks5://u:p@h:1080":  "socks5://h:1080",
		"http://10.0.0.1:3128": "http://10.0.0.1:3128",
		"1.2.3.4:8080:u:p":     "1.2.3.4:8080",
		"1.2.3.4:8080":         "1.2.3.4:8080",
	}
	for in, want := range cases {
		if got := redact(in); got != want {
			t.Fatalf("redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestURLRoundTrip(t *testing.T) {
	p := Proxy{Scheme: "socks5", Host: "h", Port: "1080", User: "u", Pass: "p"}
	u := p.URL()
	if u.String() != "socks5://u:p@h:1080" {
		t.Fatalf("url = %q", u.String())
	}
}
