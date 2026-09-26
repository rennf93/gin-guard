# gin-guard

`gin-guard` is the official Gin adapter for
[guard-core-go](https://github.com/rennf93/guard-core-go), the Go port of the
guard-core security engine. It wraps any `gin.Engine` or `gin.RouterGroup`
with the full engine pipeline: penetration detection, rate limiting, IP
banning, and verdict responses.

All security logic lives in the engine; this package is a thin shim that
translates `*gin.Context` into `guardcore.Request`, runs the engine, and
writes the block verdict (status, headers, body, then `Abort`) when one
arrives.

## Installation

```bash
go get github.com/rennf93/gin-guard@main github.com/rennf93/guard-core-go/v4@v4.1.0
```

Requires Go 1.25 or later.

The package name is `gin`, which collides with `github.com/gin-gonic/gin`
(also package `gin`), so import the adapter with an explicit alias such as
`guardgin`.

## Quick start

```go
package main

import (
	"log"

	ginlib "github.com/gin-gonic/gin"
	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
	guardgin "github.com/rennf93/gin-guard"
)

func main() {
	cfg := guardcore.DefaultSecurityConfig()
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := engine.Initialize(); err != nil {
		log.Fatal(err)
	}

	guard, err := guardgin.New(engine)
	if err != nil {
		log.Fatal(err)
	}

	router := ginlib.New()
	router.Use(guard)
	router.GET("/", func(c *ginlib.Context) {
		c.String(200, "ok")
	})

	log.Fatal(router.Run(":8080"))
}
```

## What the shim handles

- Client identity: `net.SplitHostPort` on `c.Request.RemoteAddr`. Gin's
  `c.ClientIP()` is intentionally not used: trusting proxy headers is
  policy, and trusted-proxy resolution is performed by the engine
  (`SecurityConfig.TrustedProxies`)
- Headers: first value per key, plus the `Host` header
- Body: the first `maxBodyBytes` bytes are shown to the engine, and the body
  is made replayable so your handler still receives it after inspection
- Route IDs: read from the request context (see [Usage](usage.md))
- Verdicts: written to `c.Writer` exactly (status, headers, body) and
  followed by `c.Abort()`; on a clean pass the request flows on to
  `c.Next()`
- Fail-closed: engine panics become `500` with a fixed, non-leaky message

See [Configuration](configuration.md) for engine tuning and the
[examples](https://github.com/rennf93/gin-guard/tree/master/examples) for
runnable apps.
