# 🌐 Client IP

Knowing the real client IP address is essential for request logging, rate
limiting, abuse prevention, and IP-based access control. It is also
surprisingly easy to get wrong: as soon as your server sits behind a reverse
proxy, load balancer, or CDN, `r.RemoteAddr` is the address of the *proxy*,
not the client — and headers like `X-Forwarded-For` can be freely set by any
client unless a trusted proxy overwrites them.

chi v5.3.0 introduces the `ClientIP` family of middlewares, which resolve the
real client IP **based on how your service is deployed** and make it available
via the request context.

## Why RealIP was replaced

The legacy `RealIP` middleware is deprecated and has been removed from these
docs. It had unfixable design problems:

- **Vulnerable to IP spoofing** — it blindly trusted the `X-Real-IP` and
  `X-Forwarded-For` headers, which any client can set. This resulted in three
  security advisories: GHSA-3fxj-6jh8-hvhx, GHSA-rjr7-jggh-pgcp and
  GHSA-9g5q-2w5x-hmxf.
- **It mutated `r.RemoteAddr`** — overwriting the one field that is guaranteed
  to be set by the TCP stack, hiding the original value from everything
  downstream.
- **One-size-fits-all** — it checked hard-coded headers regardless of whether
  a trusted proxy actually sets them in your deployment.

The `ClientIP` middlewares fix this by requiring you to **explicitly choose a
trust source**, and by never touching `r.RemoteAddr` — the resolved IP is
stored in the request context instead.

## Choosing the right middleware

Pick **exactly one** of the four middlewares, based on your network setup:

| Your setup | Use |
|---|---|
| Directly on the public internet, no proxy | `middleware.ClientIPFromRemoteAddr` |
| Behind nginx (`X-Real-IP`), Cloudflare (`CF-Connecting-IP`), Apache (`X-Client-IP`) | `middleware.ClientIPFromHeader("<your-trusted-header>")` |
| Behind one or more proxies whose IP ranges you can list | `middleware.ClientIPFromXFF("10.0.0.0/8", ...)` |
| Behind a known, fixed number of proxies with dynamic IPs | `middleware.ClientIPFromXFFTrustedProxies(2)` |

Insert the middleware fairly early in the stack, so that subsequent layers
(e.g. request loggers, rate limiters) can see the resolved client IP.

### ClientIPFromRemoteAddr

```go
r.Use(middleware.ClientIPFromRemoteAddr)
```

Stores the client IP read from the TCP `RemoteAddr` of the incoming request —
the IP address of whoever opened the connection to this server.

Use this when your server is **directly connected to the public internet**
with no reverse proxy in front of it. Behind a reverse proxy, `RemoteAddr` is
the proxy's IP, not the client's — use one of the other middlewares instead.

### ClientIPFromHeader

```go
// Nginx with ngx_http_realip_module:
r.Use(middleware.ClientIPFromHeader("X-Real-IP"))

// Apache with mod_remoteip:
r.Use(middleware.ClientIPFromHeader("X-Client-IP"))

// Cloudflare:
r.Use(middleware.ClientIPFromHeader("CF-Connecting-IP"))
```

Stores the client IP from a single-IP header set by your reverse proxy.

This is only safe with headers your proxy **unconditionally overwrites** on
every request. Beware: `True-Client-IP`, `X-Azure-ClientIP` and
`Fastly-Client-IP` look similar, but pass through from the client by default
in those products — don't use them unless your edge strips the inbound value.

If the header arrives with multiple values (e.g. a misconfigured proxy that
appends instead of overwrites), the **last** value wins — that's the one set
by the hop closest to your server, and therefore the most trusted. If the
last value doesn't parse, no client IP is set at all (fail-closed), rather
than falling back to earlier, less-trusted values.

### ClientIPFromXFF

```go
// Behind AWS CloudFront (or any proxy fleet with known CIDRs):
r.Use(middleware.ClientIPFromXFF(
    "13.32.0.0/15",   // CloudFront IPv4
    "52.46.0.0/18",   // CloudFront IPv4
    "2600:9000::/28", // CloudFront IPv6
))
```

Stores the client IP read from the `X-Forwarded-For` header, walking the
chain **right-to-left** and skipping any IP that falls within one of the
given trusted CIDR prefixes. The first IP that is *not* trusted is the
client.

Use this when you sit behind one or more reverse proxies whose IP ranges you
can enumerate as CIDRs. This is the **preferred XFF variant**: it stays
correct even if the number of proxy hops changes, as long as the trusted
ranges are accurate.

Notes:

- An unparseable entry mid-chain aborts the walk and leaves no client IP set
  (fail-closed) — nothing left of garbage can be safely trusted.
- Multiple `X-Forwarded-For` headers are merged per RFC 2616, so an attacker
  cannot pick which value your security logic sees by sending a duplicate
  header.
- Calling it with no arguments returns the rightmost XFF entry — safe only if
  you have exactly one trusted hop directly in front of this server (e.g.
  nginx on localhost).
- Panics at startup if any prefix is invalid.

### ClientIPFromXFFTrustedProxies

```go
// Behind exactly two trusted reverse proxies:
r.Use(middleware.ClientIPFromXFFTrustedProxies(2))
```

Stores the client IP read from the `X-Forwarded-For` header, given the
**exact number** of trusted reverse proxies between this server and the
public internet. It returns the entry added by the outermost of your trusted
proxies — the only IP in the chain that none of your proxies have allowed an
attacker to forge.

Use this when you know exactly how many proxies you sit behind, but their IP
addresses are dynamic (autoscaling proxy pools, ephemeral containers, dynamic
CDN edges), so listing CIDRs with `ClientIPFromXFF` is impractical.

**Warning:** this variant is brittle to network architecture changes. If you
add or remove a proxy level, the count silently becomes wrong and you may
start trusting an attacker-supplied IP. Prefer `ClientIPFromXFF` with
explicit trusted CIDRs whenever you can.

If the XFF chain has fewer entries than the given count (header missing, or
architecture changed), no client IP is set (fail-closed). Panics at startup
if the count is less than 1.

## Reading the client IP

Two accessor functions retrieve the resolved IP from the request context:

```go
r.Get("/", func(w http.ResponseWriter, r *http.Request) {
    // As a string — for logs, rate-limit keys, etc.
    // Returns "" if no valid client IP was resolved.
    clientIP := middleware.GetClientIP(r.Context())

    // As a netip.Addr — for typed work (prefix containment, Is4/Is6, ...)
    // without re-parsing the string. Zero value if not set; check with IsValid().
    addr := middleware.GetClientIPAddr(r.Context())
    _ = addr

    w.Write([]byte(clientIP))
})
```

All resolved IPs are normalized before storage: IPv4-mapped IPv6 addresses
(`::ffff:a.b.c.d`) are folded to plain IPv4, and IPv6 zone identifiers
carried in headers are stripped. One logical client therefore maps to a
single canonical key for logs, rate limits and ACLs — and an attacker cannot
use alternate notations to alias a trusted IP past the CIDR check.

## Full example

```go
package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)

	// Pick exactly one, based on your deployment:
	r.Use(middleware.ClientIPFromHeader("CF-Connecting-IP")) // behind Cloudflare
	// r.Use(middleware.ClientIPFromRemoteAddr)              // direct internet exposure
	// r.Use(middleware.ClientIPFromXFF("10.0.0.0/8"))       // proxies with known CIDRs
	// r.Use(middleware.ClientIPFromXFFTrustedProxies(2))    // fixed number of proxy hops

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello, " + middleware.GetClientIP(r.Context())))
	})

	http.ListenAndServe(":3333", r)
}
```

## Migrating from RealIP

1. Remove `r.Use(middleware.RealIP)`.
2. Add exactly one `ClientIPFrom*` middleware matching your deployment (see
   the table above).
3. Replace reads of `r.RemoteAddr` with `middleware.GetClientIP(r.Context())`
   wherever your code expected the real client IP. `r.RemoteAddr` is no
   longer rewritten — it always holds the address of the direct TCP peer.

## Further reading

- [Per-function godoc](https://pkg.go.dev/github.com/go-chi/chi/v5/middleware) — full semantics of each middleware
- [adam-p's "The perils of the 'real' client IP"](https://adam-p.ca/blog/2022/03/x-forwarded-for/) — the underlying threat model
