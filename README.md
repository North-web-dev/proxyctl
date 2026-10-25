# proxyctl

[![CI](https://github.com/North-web-dev/proxyctl/actions/workflows/ci.yml/badge.svg)](https://github.com/North-web-dev/proxyctl/actions/workflows/ci.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/North-web-dev/proxyctl)](https://goreportcard.com/report/github.com/North-web-dev/proxyctl) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Release](https://img.shields.io/github/v/release/North-web-dev/proxyctl?display_name=tag&sort=semver)](https://github.com/North-web-dev/proxyctl/releases)

One Go binary that **tests, scores, and rotates** proxies — with the deep checks
that naive proxy-checkers skip. Everyone who scrapes or automates fights dead,
slow, or *lying* proxies, and most checkers only answer "does it connect". The
questions that actually decide whether a proxy is usable are different:

- **Is it anonymous, or does it leak my IP?** A "working" proxy that forwards
  your real address in `X-Forwarded-For` is worse than useless.
- **Can it tunnel HTTPS (CONNECT)?** Plenty of HTTP proxies can't.
- **Does the network silently block specific SNIs?** We have watched a proxy
  happily `CONNECT` to benign hosts while resetting the one host we needed
  (vfsglobal via a certain upstream). "It connects" hid a targeted block.
- **Does this SOCKS5 proxy do UDP?** Many are TCP-only. A hCaptcha/WebRTC flow
  that needs `UDP ASSOCIATE` fails on them with no obvious reason.
- **Where does DNS resolve — here or at the proxy?** `socks5` vs `socks5h`
  changes who sees the hostname you are visiting.

`proxyctl` runs these as real probes, concurrently, and prints a table, JSON, or
a filtered list — and can then serve the healthy ones as a local rotating proxy.

It is **truthful by construction**: every value in the output comes from a real
probe. Nothing is fabricated. Where a check needs an external service the host
cannot provide (geo/ASN lookup), it is optional and off by default, and the
output says `not checked` rather than inventing a number.

## Install

```sh
go install github.com/North-web-dev/proxyctl/cmd/proxyctl@latest
# or
git clone https://github.com/North-web-dev/proxyctl && cd proxyctl
go build -o proxyctl ./cmd/proxyctl
```

## Proxy list format

One entry per line; `#` comments and blank lines are ignored. Both forms work:

```
scheme://user:pass@host:port      # scheme ∈ http, https, socks5, socks5h
host:port                         # bare; takes --default-scheme (http)
host:port:user:pass               # bare with credentials
```

## `proxyctl check`

Runs the selected checks concurrently and prints a table (or `--json`) with a
score per proxy, best first. Output below is **real, captured against in-process
mock proxies and a mock header-echo** (see `internal/testproxy`) — four live
mocks plus one dead address:

```console
$ proxyctl check --echo-url http://127.0.0.1:41989/get --connect-host 127.0.0.1:41989 proxies.txt
PROXY                      LIVE  LAT(ms)  PROTO  CONNECT  ANON       UDP   DNS     SCORE  EXIT IP
http://127.0.0.1:34335     yes   1        ok     ok       elite      n/a   remote  100    127.0.0.1
socks5h://127.0.0.1:36463  yes   1        ok     ok       elite      ok    remote  100    127.0.0.1
http://127.0.0.1:40741     yes   0        ok     ok       anonymous  n/a   remote  86     203.0.113.9
socks5://127.0.0.1:44641   yes   1        ok     ok       elite      fail  local   85     127.0.0.1
http://1.2.3.4:9           no    -        fail   fail     unknown    n/a   remote  0      -

4/5 live

socks5h://127.0.0.1:36463
  udp: ASSOCIATE granted; relay forwarded a datagram

socks5://127.0.0.1:44641
  udp: socks5: command not supported
```

The same run with `--json` emits one object per proxy:

```json
{
  "proxy": "socks5h://127.0.0.1:36463",
  "scheme": "socks5h",
  "live": true,
  "latency_ms": 1,
  "samples_ms": [1, 1, 2],
  "protocol": "ok",
  "connect": "ok",
  "anonymity": "elite",
  "exit_ip": "127.0.0.1",
  "udp": "ok",
  "udp_detail": "ASSOCIATE granted; relay forwarded a datagram",
  "dns": "remote",
  "sni": "not checked",
  "geo": "not checked",
  "score": 100
}
```

### What each check does

| Check | How it is measured | Fully implemented / best-effort |
|---|---|---|
| **live + latency** | `--probes N` requests through the proxy to the echo; the median of the successful ones is reported | fully implemented |
| **protocol** | the claimed scheme is actually spoken end-to-end (a `socks5://` that is really HTTP fails the SOCKS5 handshake) | fully implemented |
| **connect** | a real `CONNECT` tunnel to `--connect-host` (SOCKS5 CONNECT is native) | fully implemented |
| **anonymity** | routes through the proxy to the echo and inspects the headers it saw (`Via`, `X-Forwarded-For`, `X-Real-Ip`, `Forwarded`, …) and the exit IP | fully implemented; **verdict is only as honest as the echo** |
| **udp** | SOCKS5 `UDP ASSOCIATE`, then one datagram sent to the granted relay to confirm it forwards | fully implemented (socks5 only; `n/a` otherwise) |
| **dns** | `socks5` resolves locally, `socks5h`/http at the proxy | reported from scheme semantics |
| **sni** | `--sni-benign` vs `--sni-sensitive`: tunnel + TLS handshake to each and compare | best-effort inference (see limits) |
| **geo/ASN** | optional `--geo-url` with `{ip}` | off by default; never fabricated |

### Anonymity, precisely

With `--detect-real-ip` (on by default) `proxyctl` first makes **one direct,
un-proxied request** to the echo to learn its own egress IP, so it can tell a
leak from a clean exit:

- **transparent** — your real IP is visible to the echo (in a forwarding header
  or as the exit IP).
- **anonymous** — the proxy announces itself (`Via`/`X-Forwarded-For`/…) but
  your real IP is hidden.
- **elite** — no forwarding headers and no IP leak.
- **unknown** — no probe reached the echo.

If `--detect-real-ip=false` (or the direct request fails) and forwarding headers
are present, the verdict is reported as `anonymous` with the caveat that it
*could* be transparent — `proxyctl` will not guess.

### Flags

```
--json                 emit JSON instead of a table
--echo-url URL         header-echo endpoint (httpbin-compatible)   [https://httpbin.org/get]
--timeout DUR          per-check timeout                            [10s]
--concurrency N        proxies checked in parallel                  [20]
--probes N             latency probes per proxy (median reported)   [3]
--connect-host H:P     target for the CONNECT/tunnel test           [example.com:443]
--sni-benign H:P       benign host for the SNI-filter test          [off]
--sni-sensitive H:P    sensitive host for the SNI-filter test       [off]
--geo-url URL          IP-info endpoint with {ip} placeholder       [off]
--detect-real-ip       one direct request to learn egress IP        [true]
--default-scheme S     scheme for bare host:port entries            [http]
--only LEVEL           keep only elite|anonymous|transparent        (filter/table)
--require CAPS         comma list: udp,connect,live,elite
--min-score N          keep only proxies scoring at least N
```

Flags may appear before or after the list argument.

## `proxyctl filter`

Same checks, but prints only the proxies that pass the predicate — made for
piping into other tools:

```console
$ proxyctl filter --require udp,connect proxies.txt
socks5h://127.0.0.1:36463

$ proxyctl filter --only elite proxies.txt
http://127.0.0.1:34335
socks5h://127.0.0.1:36463
socks5://127.0.0.1:44641
```

Add `--json` for structured output of the survivors.

## `proxyctl rotate`

Runs a **local rotating forward proxy** over the pool: it health-checks the
upstreams, serves client requests by cycling the healthy ones, and ejects dead
ones (reviving them on the next health pass). This is poolctl's rotation job
done for network proxies. Real captured run (round-robin over four healthy mocks
plus one dead address, requests made with `curl -x`):

```console
$ proxyctl rotate --addr 127.0.0.1:18099 --probe-host 127.0.0.1:41989 proxies.txt
proxyctl rotate: 5 upstreams, 4 healthy, strategy=round-robin, listening on 127.0.0.1:18099
  GET http://127.0.0.1:41989/get via http://127.0.0.1:34335
  GET http://127.0.0.1:41989/get via http://127.0.0.1:40741
  GET http://127.0.0.1:41989/get via socks5h://127.0.0.1:36463
  GET http://127.0.0.1:41989/get via socks5://127.0.0.1:44641
  GET http://127.0.0.1:41989/get via http://127.0.0.1:34335
```

```
--addr H:P             local listen address                         [:8080]
--strategy S           round-robin | random | least-latency         [round-robin]
--probe-host H:P       host:port used for upstream health checks     [example.com:443]
--timeout DUR          per-request / per-probe timeout               [15s]
--health-interval DUR  background re-check interval                  [30s]
--default-scheme S     scheme for bare host:port entries             [http]
--quiet                do not log each forwarded request
```

Scope, honestly: it chooses one upstream per client request, supports HTTP and
HTTPS (via `CONNECT`), and ejects an upstream after repeated failures. It is a
*rotator*, not a full proxy server — no auth, no TLS on the listener (keep it on
localhost or behind a reverse proxy), and HTTP forwarding uses one upstream
connection per request.

## Scoring

The score is a transparent 0–100 weighted average over the dimensions that
*apply* to a given proxy — not a magic number. A dead or non-conformant proxy
scores **0**. Otherwise:

| Dimension | Weight | Sub-score |
|---|---|---|
| latency | 40 | `1.0` at ≤100 ms, `0.0` at ≥3000 ms, linear between |
| anonymity | 30 | elite `1.0`, anonymous `0.6`, transparent `0.2`, unknown `0.4` |
| connect | 15 | `1.0` if a tunnel was established, else `0.0` |
| udp | 15 | SOCKS5 only — `1.0` if `UDP ASSOCIATE` worked, else `0.0` |

```
score = 100 × Σ(weightᵢ × sub_scoreᵢ) / Σ(weightᵢ for applicable i)
```

UDP is **excluded from the denominator for HTTP/HTTPS proxies** (they cannot
have it), so they are not punished for a feature that does not apply — which is
why an elite, fast HTTP proxy scores 100 while an otherwise-identical SOCKS5 that
lacks UDP scores 85. The weights and the 100 ms/3000 ms latency bounds live in
`internal/score` as named constants.

## Honest limits

- **Anonymity is only as honest as the echo.** The verdict is computed from what
  the echo reports receiving. Point `--echo-url` at an endpoint you trust;
  anything httpbin-compatible (`{"origin": "...", "headers": {...}}`) works.
- **SNI-filter detection is an inference, not proof.** A reset on the sensitive
  host and success on the benign one is *consistent with* SNI filtering, but a
  plain outage, geo-block, or rate-limit can look the same. `proxyctl` reports
  what it observed and labels inconclusive cases as such; both hosts are
  user-supplied.
- **DNS mode is read from the scheme**, which is the contract `proxyctl` honors
  when dialing (`socks5h` sends the hostname to the proxy; `socks5` resolves
  locally). It is not an independent leak test.
- **Geo/ASN is optional and never fabricated.** Without `--geo-url` the field is
  `not checked`.
- **UDP probe** confirms `ASSOCIATE` and that *a* datagram is relayed; it does
  not benchmark throughput or NAT behavior.
- **Credentials** are read from the list and held in memory; this is not a
  secret manager.

## Relation to poolctl

`proxyctl` supersedes the proxy-rotation idea in our earlier
[`North-web-dev/poolctl`](https://github.com/North-web-dev/poolctl). poolctl
remains a fine **token/API-key** pool manager and LLM-gateway; what it did for
*network proxies* (health-check a pool and hand out a live one) is done here
properly, with real protocol-aware checks and a scheme-aware rotating listener.
Use poolctl for API keys, `proxyctl` for proxies.

## Development

```sh
go build ./... && go vet ./...
gofmt -l .
go test ./... -race
```

Tests stand up in-process mock HTTP/CONNECT and SOCKS5 (incl. UDP ASSOCIATE)
proxies and a mock echo (`internal/testproxy`); they never touch a live external
proxy.

## Disclaimer

Provided **as is, without warranty of any kind**. `proxyctl` only probes the
proxies you point it at and runs the checks you configure. You are responsible
for using it against infrastructure you are permitted to test and for complying
with the Terms of Service of any endpoint involved. The authors accept no
liability for misuse.

## Support

If `proxyctl` saves you some time, a ⭐ on the repo is appreciated — and so is a tip:

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |
