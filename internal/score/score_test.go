package score

import (
	"testing"

	"github.com/North-web-dev/proxyctl/internal/checks"
)

func TestCompute(t *testing.T) {
	tests := []struct {
		name string
		r    checks.Result
		want int
	}{
		{"dead scores zero", checks.Result{Live: false, Protocol: checks.Fail}, 0},
		{"non-conformant scores zero", checks.Result{Live: true, Protocol: checks.Fail}, 0},
		{
			"elite fast http with connect",
			checks.Result{Live: true, Protocol: checks.OK, LatencyMS: 50,
				Anonymity: checks.Elite, Connect: checks.OK, UDP: checks.NA},
			100,
		},
		{
			"transparent slow http no connect",
			checks.Result{Live: true, Protocol: checks.OK, LatencyMS: 3000,
				Anonymity: checks.Transparent, Connect: checks.Fail, UDP: checks.NA},
			// latency 0, anon 0.2*30, connect 0 over denom 85 => 6/85 => 7
			7,
		},
		{
			"socks5 elite fast with udp",
			checks.Result{Live: true, Protocol: checks.OK, LatencyMS: 100,
				Anonymity: checks.Elite, Connect: checks.OK, UDP: checks.OK},
			100,
		},
		{
			"socks5 no udp is penalized vs http na",
			checks.Result{Live: true, Protocol: checks.OK, LatencyMS: 100,
				Anonymity: checks.Elite, Connect: checks.OK, UDP: checks.Fail},
			// (40 + 30 + 15 + 0) / 100 = 85
			85,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := Compute(tt.r)
			if got != tt.want {
				t.Fatalf("Compute = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUDPNotApplicableNotPenalized(t *testing.T) {
	httpProxy := checks.Result{Live: true, Protocol: checks.OK, LatencyMS: 100,
		Anonymity: checks.Elite, Connect: checks.OK, UDP: checks.NA}
	socksNoUDP := httpProxy
	socksNoUDP.UDP = checks.Fail
	hs, _ := Compute(httpProxy)
	ss, _ := Compute(socksNoUDP)
	if hs <= ss {
		t.Fatalf("http (udp n/a) %d should outscore socks5 lacking udp %d", hs, ss)
	}
}

func TestLatencyMonotonic(t *testing.T) {
	base := checks.Result{Live: true, Protocol: checks.OK, Anonymity: checks.Elite,
		Connect: checks.OK, UDP: checks.NA}
	fast, slow := base, base
	fast.LatencyMS = 100
	slow.LatencyMS = 2000
	fs, _ := Compute(fast)
	ss, _ := Compute(slow)
	if fs <= ss {
		t.Fatalf("faster proxy %d should outscore slower %d", fs, ss)
	}
}
