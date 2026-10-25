// Command proxyctl tests, scores, filters, and rotates proxies.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/North-web-dev/proxyctl/internal/checks"
	"github.com/North-web-dev/proxyctl/internal/proxyspec"
	"github.com/North-web-dev/proxyctl/internal/rotate"
	"github.com/North-web-dev/proxyctl/internal/score"
)

const defaultEcho = "https://httpbin.org/get"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "check":
		err = cmdCheck(os.Args[2:], false)
	case "filter":
		err = cmdCheck(os.Args[2:], true)
	case "rotate":
		err = cmdRotate(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("proxyctl " + version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

var version = "v0.1.0"

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: proxyctl %s [flags] <list>\n\nflags:\n", name)
		fs.PrintDefaults()
	}
	return fs
}

// parsePositional parses flags while tolerating a single positional argument
// placed anywhere in the list (stdlib flag otherwise stops at the first one).
func parsePositional(fs *flag.FlagSet, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	positional := ""
	for fs.NArg() > 0 {
		rest := fs.Args()
		if positional == "" {
			positional = rest[0]
		}
		if err := fs.Parse(rest[1:]); err != nil {
			return "", err
		}
	}
	return positional, nil
}

func usage() {
	fmt.Fprint(os.Stderr, `proxyctl — deep proxy checker, scorer, and rotator

USAGE
  proxyctl check  <list>   run checks, print a table (+ --json) with a score
  proxyctl filter <list>   run checks, emit only proxies passing a predicate
  proxyctl rotate <list>   run a local rotating forward proxy over the pool

  <list> is a file path or - for stdin. Entries: scheme://user:pass@host:port
  or bare host:port[:user:pass]. Lines starting with # are ignored.

Run "proxyctl <command> -h" for per-command flags.
`)
}

func cmdCheck(args []string, filter bool) error {
	fs := newFlagSet("check")
	var (
		jsonOut     = fs.Bool("json", false, "emit JSON instead of a table")
		echoURL     = fs.String("echo-url", defaultEcho, "header-echo endpoint (httpbin-compatible)")
		timeout     = fs.Duration("timeout", 10*time.Second, "per-check timeout")
		concurrency = fs.Int("concurrency", 20, "max proxies checked in parallel")
		probes      = fs.Int("probes", 3, "latency probes per proxy (median reported)")
		connectHost = fs.String("connect-host", "example.com:443", "host:port for the CONNECT/tunnel test")
		sniBenign   = fs.String("sni-benign", "", "benign host:port for SNI-filter test (optional)")
		sniSens     = fs.String("sni-sensitive", "", "sensitive host:port for SNI-filter test (optional)")
		geoURL      = fs.String("geo-url", "", "IP-info endpoint with {ip} placeholder (optional)")
		realIP      = fs.Bool("detect-real-ip", true, "make one direct request to learn egress IP (anonymity accuracy)")
		defScheme   = fs.String("default-scheme", "http", "scheme for bare host:port entries")
		only        = fs.String("only", "", "keep only this anonymity level (elite|anonymous|transparent)")
		require     = fs.String("require", "", "comma list of required capabilities: udp,connect,live")
		minScore    = fs.Int("min-score", 0, "keep only proxies scoring at least this")
	)
	path, err := parsePositional(fs, args)
	if err != nil {
		return err
	}
	proxies, perr, err := loadProxies(path, *defScheme)
	if err != nil {
		return err
	}
	for _, e := range perr {
		fmt.Fprintln(os.Stderr, "skip:", e)
	}
	if len(proxies) == 0 {
		return fmt.Errorf("no valid proxies to check")
	}

	opts := checks.Options{
		EchoURL: *echoURL, Timeout: *timeout, Probes: *probes, ConnectHost: *connectHost,
		SNIBenign: *sniBenign, SNISensitive: *sniSens, GeoURL: *geoURL, DetectRealIP: *realIP,
	}
	results := runAll(proxies, opts, *concurrency)
	for i := range results {
		results[i].Score, _ = score.Compute(results[i])
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].Score > results[j].Score })

	pred := predicate{only: *only, require: splitCSV(*require), minScore: *minScore}
	if filter {
		kept := results[:0]
		for _, r := range results {
			if pred.pass(r) {
				kept = append(kept, r)
			}
		}
		results = kept
		return emitFiltered(results, *jsonOut)
	}
	if *jsonOut {
		return emitJSON(results)
	}
	printTable(results)
	return nil
}

func cmdRotate(args []string) error {
	fs := newFlagSet("rotate")
	var (
		addr      = fs.String("addr", "127.0.0.1:8080", "local listen address for the rotating proxy")
		strategy  = fs.String("strategy", "round-robin", "round-robin | random | least-latency")
		probeHost = fs.String("probe-host", "example.com:443", "host:port used for upstream health checks")
		timeout   = fs.Duration("timeout", 15*time.Second, "per-request / per-probe timeout")
		interval  = fs.Duration("health-interval", 30*time.Second, "health re-check interval")
		defScheme = fs.String("default-scheme", "http", "scheme for bare host:port entries")
		auth      = fs.String("auth", "", "require client Proxy-Authorization as user:pass (Basic)")
		quiet     = fs.Bool("quiet", false, "do not log each forwarded request")
	)
	path, err := parsePositional(fs, args)
	if err != nil {
		return err
	}
	proxies, perr, err := loadProxies(path, *defScheme)
	if err != nil {
		return err
	}
	for _, e := range perr {
		fmt.Fprintln(os.Stderr, "skip:", e)
	}
	if len(proxies) == 0 {
		return fmt.Errorf("no valid upstream proxies")
	}

	authHeader := ""
	if *auth != "" {
		user, pass, ok := strings.Cut(*auth, ":")
		if !ok {
			return fmt.Errorf("--auth must be user:pass")
		}
		authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	if !rotate.IsLoopbackAddr(*addr) && authHeader == "" {
		return fmt.Errorf("refusing to bind non-loopback address %q as an open proxy; "+
			"set --auth user:pass to require client authentication, or bind a loopback address", *addr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool := rotate.NewPool(proxies, rotate.Strategy(*strategy), *probeHost, *timeout)
	pool.Run(ctx, *interval)
	st := pool.Stats()
	authNote := "no client auth"
	if authHeader != "" {
		authNote = "client auth required"
	}
	fmt.Fprintf(os.Stderr, "proxyctl rotate: %d upstreams, %d healthy, strategy=%s, %s, listening on %s\n",
		st.Total, st.Healthy, *strategy, authNote, *addr)

	srv := &rotate.Server{Pool: pool, Timeout: *timeout, Auth: authHeader}
	if !*quiet {
		srv.Log = func(f string, a ...any) { fmt.Fprintf(os.Stderr, "  "+f+"\n", a...) }
	}
	err = srv.ListenAndServe(ctx, *addr)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func runAll(proxies []proxyspec.Proxy, opts checks.Options, concurrency int) []checks.Result {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]checks.Result, len(proxies))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p proxyspec.Proxy) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout*4+5*time.Second)
			defer cancel()
			results[i] = checks.Run(ctx, p, opts)
		}(i, p)
	}
	wg.Wait()
	return results
}

type predicate struct {
	only     string
	require  []string
	minScore int
}

func (p predicate) pass(r checks.Result) bool {
	if p.only != "" && r.Anonymity != p.only {
		return false
	}
	if r.Score < p.minScore {
		return false
	}
	for _, req := range p.require {
		switch req {
		case "live":
			if !r.Live {
				return false
			}
		case "connect":
			if r.Connect != checks.OK {
				return false
			}
		case "udp":
			if r.UDP != checks.OK {
				return false
			}
		case "elite":
			if r.Anonymity != checks.Elite {
				return false
			}
		}
	}
	return true
}

func printTable(results []checks.Result) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PROXY\tLIVE\tLAT(ms)\tPROTO\tCONNECT\tANON\tUDP\tDNS\tSCORE\tEXIT IP")
	live := 0
	for _, r := range results {
		if r.Live {
			live++
		}
		lat := "-"
		if r.LatencyMS >= 0 {
			lat = fmt.Sprintf("%d", r.LatencyMS)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			r.Proxy, yn(r.Live), lat, r.Protocol, r.Connect, r.Anonymity, r.UDP, r.DNS, r.Score, dash(r.ExitIP))
	}
	tw.Flush()
	fmt.Printf("\n%d/%d live\n", live, len(results))
	for _, r := range results {
		if r.SNI != "not checked" || r.Geo != "not checked" || r.UDPDetail != "" {
			fmt.Printf("\n%s\n", r.Proxy)
			if r.SNI != "not checked" {
				fmt.Printf("  sni: %s\n", r.SNI)
			}
			if r.UDPDetail != "" {
				fmt.Printf("  udp: %s\n", r.UDPDetail)
			}
			if r.Geo != "not checked" {
				fmt.Printf("  geo: %s\n", r.Geo)
			}
		}
	}
}

func emitJSON(results []checks.Result) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func emitFiltered(results []checks.Result, jsonOut bool) error {
	if jsonOut {
		return emitJSON(results)
	}
	for _, r := range results {
		fmt.Println(r.Proxy)
	}
	return nil
}

func loadProxies(path, defScheme string) ([]proxyspec.Proxy, []error, error) {
	var data []byte
	var err error
	if path == "" || path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read list: %w", err)
	}
	proxies, perr := proxyspec.ParseList(string(data), defScheme)
	return proxies, perr, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
