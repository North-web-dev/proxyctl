// Package score turns a check Result into a transparent 0..100 number.
//
// The formula is a weighted average over the dimensions that apply to a given
// proxy. A dead or non-conformant proxy scores 0. Otherwise:
//
//	latency   (weight 40): 1.0 at or below FastMS, 0.0 at or above SlowMS, linear between.
//	anonymity (weight 30): elite 1.0, anonymous 0.6, transparent 0.2, unknown 0.4.
//	connect   (weight 15): 1.0 if a tunnel was established, else 0.0.
//	udp       (weight 15): socks5 only — 1.0 if UDP ASSOCIATE worked, else 0.0.
//
// UDP is excluded from the denominator for http/https proxies (not applicable),
// so they are not punished for lacking a feature they cannot have.
package score

import "github.com/North-web-dev/proxyctl/internal/checks"

// Tunable latency bounds in milliseconds.
const (
	FastMS = 100
	SlowMS = 3000
)

// Weights for each dimension.
const (
	WLatency   = 40
	WAnonymity = 30
	WConnect   = 15
	WUDP       = 15
)

// Breakdown exposes the per-dimension sub-scores for transparency.
type Breakdown struct {
	Latency   float64
	Anonymity float64
	Connect   float64
	UDP       float64
	Total     int
}

func latencyScore(ms int64) float64 {
	if ms < 0 {
		return 0
	}
	if ms <= FastMS {
		return 1
	}
	if ms >= SlowMS {
		return 0
	}
	return float64(SlowMS-ms) / float64(SlowMS-FastMS)
}

func anonymityScore(level string) float64 {
	switch level {
	case checks.Elite:
		return 1.0
	case checks.Anonymous:
		return 0.6
	case checks.Transparent:
		return 0.2
	default:
		return 0.4
	}
}

func boolScore(status string) float64 {
	if status == checks.OK {
		return 1
	}
	return 0
}

// Compute returns the integer score and the breakdown that produced it.
func Compute(r checks.Result) (int, Breakdown) {
	if !r.Live || r.Protocol != checks.OK {
		return 0, Breakdown{}
	}
	b := Breakdown{
		Latency:   latencyScore(r.LatencyMS),
		Anonymity: anonymityScore(r.Anonymity),
		Connect:   boolScore(r.Connect),
		UDP:       boolScore(r.UDP),
	}
	num := b.Latency*WLatency + b.Anonymity*WAnonymity + b.Connect*WConnect
	den := float64(WLatency + WAnonymity + WConnect)
	if r.UDP != checks.NA {
		num += b.UDP * WUDP
		den += WUDP
	}
	b.Total = int((num/den)*100 + 0.5)
	return b.Total, b
}
