---
name: gin-guard
description: Use when wiring guard-core-go security into a Go Gin service, or when working in github.com/rennf93/gin-guard: build the middleware with guardgin.New(engine, opts...) (package gin, alias it to avoid clashing with github.com/gin-gonic/gin), tune WithMaxBodyBytes (default 262144) and WithLogger, attach route identity with WithRouteID on the request context, understand requestShim adaptation of *gin.Context to guardcore.Request including the bounded body prefix scan, idempotent Body(), and replay so handlers still receive the full stream, exact verdict translation into gin.Writer writes followed by c.Abort(), fail-closed 500 on engine malfunction, and Redis-backed integration tests via REDIS_HOST and go test -tags integration.
---

# gin-guard

Gin middleware adapter for [guard-core-go](https://github.com/rennf93/guard-core-go). Translates `*gin.Context` into the guardcore request surface, runs the engine, and translates verdicts to exact Gin responses (status, headers, body, then abort). Contains no security logic itself. Module: `github.com/rennf93/gin-guard`, Go `1.25.0`, no release tag yet.

## Quick Reference

| Identifier | Kind | Notes |
| --- | --- | --- |
| `guardgin.New(engine, opts...)` | func | Returns `(gin.HandlerFunc, error)`; errors on nil engine |
| `guardgin.WithMaxBodyBytes(n)` | Option | Bounds engine body scan; ignored when `n <= 0`; default 262144 |
| `guardgin.WithLogger(l)` | Option | Fail-closed logger; ignored when nil; default `log.Default()` |
| `guardgin.WithRouteID(ctx, id)` | func | Returns a context carrying the route ID for `engine.Routes` lookups |
| `guardgin.DefaultMaxBodyBytes` | const | `262144` bytes (256 KiB) |

Behavior contract: the engine sees at most `MaxBodyBytes` of the body prefix; payloads beyond the bound are not scanned; the handler still receives the full body via replay. A verdict short-circuits the handler (`c.Abort()`). An engine error or panic produces a 500 via `engine.CreateErrorResponse(500, "Security check failed")`. On a clean pass the adapter adds no headers and calls `c.Next()`.

## Installation

```sh
go get github.com/rennf93/gin-guard@main github.com/rennf93/guard-core-go/v4@v4.0.4
```

The package name is `gin`, which collides with `github.com/gin-gonic/gin`, so import the adapter with an alias:

```go
import (
    ginlib "github.com/gin-gonic/gin"
    guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
    guardgin "github.com/rennf93/gin-guard"
)
```

## Setup

```go
cfg := guardcore.DefaultSecurityConfig()
engine, err := guardcore.NewEngine(cfg)
if err != nil { log.Fatal(err) }
if err := engine.Initialize(); err != nil { log.Fatal(err) }

guard, err := guardgin.New(engine) // or guardgin.New(engine, guardgin.WithMaxBodyBytes(65536))
if err != nil { log.Fatal(err) }

router := ginlib.New()
router.Use(guard)
router.GET("/", func(c *ginlib.Context) { c.String(200, "ok") })
log.Fatal(router.Run(":8080"))
```

`Initialize` is required by the core. Redis connectivity is a guard-core-go concern; this adapter never talks to Redis directly.

## guardgin.New

```go
func New(engine *guardcore.Engine, opts ...Option) (gin.HandlerFunc, error)
```

- Rejects a nil engine with `errors.New("engine must not be nil")`.
- Returns a `gin.HandlerFunc`, so it composes with `router.Use` and route groups anywhere in the Gin chain.
- The middleware builds a `requestShim` from `c.Request`, calls `engine.Check`, then either applies the verdict and aborts, or calls `c.Next()`.
- Engine calls are wrapped in a recover: a panic from `engine.Check` (for example inside a user `CustomRequestCheck`) becomes an error and takes the fail-closed path.

## Options: WithMaxBodyBytes and WithLogger

```go
func WithMaxBodyBytes(maxBodyBytes int64) Option
func WithLogger(logger *log.Logger) Option
```

- `WithMaxBodyBytes` sets the byte bound scanned by the engine. Non-positive values are ignored and the default `DefaultMaxBodyBytes` (262144) applies. The bound also caps `ReadBodyPrefix`.
- `WithLogger` replaces the logger used on engine malfunction. Nil is ignored; the default is `log.Default()`. The message logged is `guardcore gin: engine malfunction, failing closed: <err>`.
- Invalid option values never cause an error from `New`; they are silently ignored.

## WithRouteID and Route Matching

```go
func WithRouteID(ctx context.Context, routeID string) context.Context
```

- Stores the route ID under a private context key. `requestShim` copies it to `guardcore.RequestState.GuardRouteID`.
- Route policy itself lives in the core: register with `engine.Routes.Register("name", func(rc *guardcore.RouteConfig) { rc.BypassedChecks = []string{"all"} })`.
- In Gin the guard runs as middleware, so attach the ID in a middleware registered before it: `c.Request = c.Request.WithContext(guardgin.WithRouteID(c.Request.Context(), "name"))`. Without a route ID in context the request is evaluated under default policy.

## Request Adaptation: requestShim and Body Replay

`requestShim` implements `guardcore.Request` over `c.Request` and is the whole adaptation surface.

- `URLPath`, `URLScheme` (https when `req.TLS != nil`), `URLFull`, `URLReplaceScheme`, `Method` (uppercased, defaults to GET), `ClientHost` (via `net.SplitHostPort` on `RemoteAddr`, not Gin's `c.ClientIP()`).
- `Headers`: first value per header name only, plus an explicit `Host` from `req.Host`.
- `QueryParams`: first parsed value per key.
- `Body()` returns the cached prefix (bounded by `MaxBodyBytes`) and is idempotent.
- `ReadBodyPrefix(maxBytes)` extends the cache contiguously up to the bound; negative values clamp to 0, values above the bound clamp to `MaxBodyBytes`.
- `newRequestShim` replaces `c.Request.Body` with a `replayBody`. Reads first return bytes the engine consumed from the cache, then stream the untouched remainder from the source. `Close` closes the original body.

## Footguns

- Package name collision: `github.com/rennf93/gin-guard` and `github.com/gin-gonic/gin` are both package `gin`; always alias the adapter (for example `guardgin`).
- The engine only scans the first `MaxBodyBytes` bytes. A malicious marker beyond the bound is not detected and the request passes; verify bounds when a route accepts large payloads.
- `WithMaxBodyBytes(-1)` and `WithLogger(nil)` are silently ignored, not errors. Guard against typos that drop real configuration.
- Client identity comes from `RemoteAddr`, never `c.ClientIP()`. Do not "fix" this in the adapter; proxy trust is core configuration territory.
- Integration tests SKIP when `REDIS_HOST` is unset. `go test -tags integration ./...` can look green while Redis-backed coverage never ran.
- A panic inside a core custom check is converted to a 500. That is intentional fail-closed behavior, not a crash.
- Verdict headers, status, and body come from the core verbatim. Do not add or rewrite response headers in this adapter.
- Do not push to `main` (protected) and do not push `v*` tags; a tag push triggers the Release Gate workflow.

## Related Projects

- [guard-core-go](https://github.com/rennf93/guard-core-go): the engine this adapter wraps. All detection, rate limiting, bans, configuration, and Redis integration live there; import it as `guardcore "github.com/rennf93/guard-core-go/v4/guardcore"`.
- [nethttp-guard](https://github.com/rennf93/nethttp-guard): the sibling net/http adapter with the same surface and behavior contract.
