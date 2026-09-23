// Command simple_app is a minimal guarded Gin server. The Gin bridging lives
// in the gin-guard adapter (this repository) and every security decision
// comes from the guard-core-go engine, so the demonstration wiring is the
// canonical one:
//
//	SecurityConfig -> NewEngine -> Initialize -> guardgin.New -> router.Use
//
// Unlike guard-core-go's own simple_app, no request shim is written here: the
// adapter performs request translation, bounded body scanning with replay,
// exact verdict translation, and fail-closed handling.
package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	ginlib "github.com/gin-gonic/gin"
	guardgin "github.com/rennf93/gin-guard"
	guardcore "github.com/rennf93/guard-core-go/v4/guardcore"
)

func main() {
	cfg, err := guardcore.NewSecurityConfig(func(c *guardcore.SecurityConfig) {
		// Rate limiting: global 30 req/60s per client, with a strict
		// per-endpoint override used by the demo and the live smoke test.
		c.EnableRateLimiting = true
		c.RateLimit = 30
		c.RateLimitWindow = 60
		c.EndpointRateLimits = map[string]guardcore.RateLimitEntry{
			"/rate/strict": {Requests: 1, Window: 10},
		}

		// IP banning: 5 violations in the window earns a 5 minute ban.
		c.EnableIPBanning = true
		c.AutoBanThreshold = 5
		c.AutoBanDuration = 300

		// Demo determinism: a single xss violation bans the client right
		// away, so the live smoke can assert the 200 -> 403 transition
		// without replaying a loop. Use realistic thresholds in production.
		c.ThreatBanConfig = map[string]guardcore.ThreatBanEntry{
			"xss": {Threshold: 1, Duration: 300},
		}

		// Penetration detection: all categories, default thresholds.
		c.EnablePenetrationDetection = true

		// The Python engine automatically skips ssrf scanning for address
		// headers (host, x-forwarded-for, x-real-ip, ...). This port does
		// not apply that built-in exclusion yet, and the Gin adapter passes
		// an explicit Host header (see request.go), so mirror the exclusion
		// here; otherwise a plain "Host: localhost" request is flagged as
		// ssrf. Excluding these headers only narrows detection scanning, it
		// does not affect trusted-proxy client IP resolution.
		c.ExcludedDetectionHeaders = map[string]bool{
			"host": true, "origin": true, "via": true,
			"x-forwarded-for": true, "x-forwarded-host": true,
			"x-real-ip": true, "x-client-ip": true,
			"x-cluster-client-ip": true, "cf-connecting-ip": true,
			"true-client-ip": true, "fly-client-ip": true,
			"x-envoy-external-address": true,
		}

		// Blocked user agents (regex patterns).
		c.BlockedUserAgents = []string{"badbot", "evil-crawler", "sqlmap"}

		// Custom block bodies, keyed by status code.
		c.CustomErrorResponses = map[int]string{
			403: "Blocked by gin-guard",
		}

		// Paths the pipeline never sees.
		c.ExcludePaths = []string{
			"/docs", "/redoc", "/openapi.json", "/favicon.ico", "/static", "/health",
		}

		// OnBlock is the telemetry seam of this port. Guard Agent
		// integration is not implemented in guard-core-go yet (setting
		// EnableAgent fails config validation), so wire the agent from
		// here: forward these payloads to guard-agent-go
		// (https://github.com/rennf93/guard-agent-go) once its event
		// pipeline accepts engine events. The payload carries check_name,
		// reason, trigger_info, passive_mode, client_ip, path, method, and
		// status_code.
		c.OnBlock = func(req guardcore.Request, payload map[string]any) {
			log.Printf("guard blocked %s %s from %s via %s: %s",
				payload["method"], payload["path"], payload["client_ip"],
				payload["check_name"], payload["reason"])
		}

		// Redis: enabled when REDIS_URL is set (docker compose sets it to
		// redis://redis:6379). Without Redis the managers fall back to
		// in-process state, which is fine for a demo but not for replicas.
		if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
			c.EnableRedis = true
			c.RedisURL = redisURL
		} else {
			c.EnableRedis = false
		}
		if prefix := os.Getenv("REDIS_PREFIX"); prefix != "" {
			c.RedisPrefix = prefix
		}
	})
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		log.Fatalf("engine: %v", err)
	}
	// Idempotent; connects Redis when enabled and primes cloud IP ranges.
	if err := engine.Initialize(); err != nil {
		log.Fatalf("initialize: %v", err)
	}
	defer func() {
		if err := engine.Close(); err != nil {
			log.Printf("engine close: %v", err)
		}
	}()

	// New returns a gin.HandlerFunc, so the guard composes with router.Use
	// and can sit anywhere in a chain. The options below are the defaults,
	// made explicit: bound the bytes the engine scans, and log fail-closed
	// malfunctions through the standard logger.
	guard, err := guardgin.New(engine,
		guardgin.WithMaxBodyBytes(guardgin.DefaultMaxBodyBytes),
		guardgin.WithLogger(log.Default()),
	)
	if err != nil {
		log.Fatalf("middleware: %v", err)
	}

	ginlib.SetMode(ginlib.ReleaseMode)
	router := ginlib.New()
	// Recovery stays outermost so handler panics are contained; the guard
	// runs next so blocked requests never reach another middleware.
	router.Use(ginlib.Recovery())
	router.Use(guard)
	router.GET("/", info)
	router.GET("/health", health)
	router.POST("/echo", echo)
	router.GET("/rate/strict", strict)
	router.GET("/search", search)

	log.Println("simple_app listening on :8080")
	log.Fatal(router.Run(":8080"))
}

func info(c *ginlib.Context) {
	c.JSON(http.StatusOK, ginlib.H{
		"app":       "gin-guard simple_app",
		"endpoints": []string{"/health", "/echo (POST)", "/rate/strict", "/search?q="},
	})
}

func health(c *ginlib.Context) {
	c.JSON(http.StatusOK, ginlib.H{"status": "ok"})
}

// echo proves the adapter's body contract: the engine scans a bounded prefix
// and the replay wrapper hands the handler the full, untouched body.
func echo(c *ginlib.Context) {
	if c.Request.Method != http.MethodPost {
		c.String(http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, "unreadable body")
		return
	}
	c.JSON(http.StatusOK, ginlib.H{"echo": true, "bytes": len(body)})
}

func strict(c *ginlib.Context) {
	c.JSON(http.StatusOK, ginlib.H{
		"endpoint": "/rate/strict",
		"limit":    "1 request per 10 seconds",
	})
}

func search(c *ginlib.Context) {
	q := c.Query("q")
	if strings.ContainsAny(q, "<'") {
		// The engine should have blocked requests that reach this handler
		// with hostile input; treat this as defense in depth and never echo
		// or log the payload.
		c.String(http.StatusForbidden, "Blocked by gin-guard")
		return
	}
	c.JSON(http.StatusOK, ginlib.H{"query": q, "results": []string{}})
}
