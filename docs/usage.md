# Usage

## Constructor

```go
func New(engine *guardcore.Engine, opts ...Option) (gin.HandlerFunc, error)
```

`New` returns a `gin.HandlerFunc`, so the guard composes with `router.Use`
(or `group.Use`) anywhere in a handler chain. It rejects a nil engine with
an error; invalid option values are silently ignored so a bad flag can never
weaken security.

## Options

| Option | Default | Purpose |
|---|---|---|
| `WithMaxBodyBytes(int64)` | `DefaultMaxBodyBytes` (262144) | Body prefix handed to the engine for inspection |
| `WithLogger(*log.Logger)` | `log.Default()` | Receive fail-closed diagnostics (prefix `guardcore gin: ...`) |

```go
guard, err := guardgin.New(engine,
    guardgin.WithMaxBodyBytes(64*1024),
    guardgin.WithLogger(log.New(os.Stderr, "guardgin ", log.LstdFlags)),
)
```

## Route IDs

Per-route configuration lives in the engine's `RouteRegistry`. Attach a route
ID to the request context in a middleware registered before the guard: Gin
runs middleware in registration order, so a group-level middleware would run
after the guard and the engine would never see the ID.

```go
engine.Routes.Register("admin", func(rc *guardcore.RouteConfig) {
    rc.RequiredHeaders = guardcore.RequiredHeaders{
        {Name: "X-Admin-Token", Value: "secret"},
    }
})

routeIDs := map[string]string{
    "/admin/banned": "admin",
    "/admin/ban":    "admin",
    "/admin/unban":  "admin",
}

// Keys are gin route patterns (c.FullPath()), so parameterized routes map
// cleanly.
router.Use(func(c *ginlib.Context) {
    if routeID, ok := routeIDs[c.FullPath()]; ok {
        c.Request = c.Request.WithContext(guardgin.WithRouteID(c.Request.Context(), routeID))
    }
})
router.Use(guard) // the mapper must run before the guard
```

## Verdicts

When the engine returns a block verdict, the middleware writes the verdict
status code, headers, and body to `c.Writer`, calls `c.Abort()`, and never
calls the wrapped handler:

| Situation | Status | Body |
|---|---|---|
| Banned IP | 403 | `IP address banned` |
| Suspicious content | 400 | `Suspicious activity detected` |
| Rate limit exceeded | 429 | `Too many requests` |

Bodies can be overridden globally through `SecurityConfig.CustomErrorResponses`.

## Fail-closed behavior

If the engine check panics, the middleware recovers, logs through the
`WithLogger` sink, and responds `500 Security check failed` rather than
letting the request through.
