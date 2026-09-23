//go:build integration

package gin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	ginlib "github.com/gin-gonic/gin"
	"github.com/rennf93/guard-core-go/v4/guardcore"
)

func newIntegrationMiddleware(t *testing.T) (ginlib.HandlerFunc, *guardcore.Engine) {
	t.Helper()
	host := os.Getenv("REDIS_HOST")
	if host == "" {
		t.Skip("REDIS_HOST not set")
	}
	cfg := guardcore.DefaultSecurityConfig()
	cfg.EnableRedis = true
	cfg.RedisURL = "redis://" + host + ":6379"
	cfg.RedisPrefix = "guard_core_gin_test:"
	cfg.RedisFailOpen = false
	engine, err := guardcore.NewEngine(cfg)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if err := engine.Initialize(); err != nil {
		t.Fatalf("engine initialize: %v", err)
	}
	guard, err := New(engine)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}
	t.Cleanup(func() {
		_, _ = engine.Redis.DeletePattern("banned_ips:*")
		_, _ = engine.Redis.DeletePattern("rate_limit:rate:*")
		_ = engine.Close()
	})
	return guard, engine
}

func serveBlocked(t *testing.T, guard ginlib.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	router := ginlib.New()
	router.Use(guard)
	router.Any("/*wildcard", func(c *ginlib.Context) {
		t.Fatal("blocked request must not reach the handler")
	})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, r)
	return rec
}

func TestIntegrationMiddlewareBlocksBannedIP(t *testing.T) {
	guard, engine := newIntegrationMiddleware(t)
	bannedIP := "203.0.113.60"
	applied, err := engine.Ban.Ban(bannedIP, 120, "integration-test")
	if err != nil || !applied {
		t.Fatalf("ban not applied: %v %v", applied, err)
	}
	blocked := httptest.NewRequest("GET", "/api", nil)
	blocked.RemoteAddr = bannedIP + ":4711"
	rec := serveBlocked(t, guard, blocked)
	if rec.Code != 403 || rec.Body.String() != guardcore.IPBanBlockedMessage {
		t.Fatalf("banned IP must be blocked with 403 %q, got %d %q", guardcore.IPBanBlockedMessage, rec.Code, rec.Body.String())
	}
}

func TestIntegrationMiddlewareStartupWiringAcrossEngines(t *testing.T) {
	_, first := newIntegrationMiddleware(t)
	bannedIP := "203.0.113.61"
	applied, err := first.Ban.Ban(bannedIP, 120, "integration-test")
	if err != nil || !applied {
		t.Fatalf("ban not applied: %v %v", applied, err)
	}
	secondGuard, _ := newIntegrationMiddleware(t)
	blocked := httptest.NewRequest("GET", "/api", nil)
	blocked.RemoteAddr = bannedIP + ":4711"
	rec := serveBlocked(t, secondGuard, blocked)
	if rec.Code != 403 || rec.Body.String() != guardcore.IPBanBlockedMessage {
		t.Fatalf("second engine must see the redis-backed ban after startup wiring, got %d %q", rec.Code, rec.Body.String())
	}
	allowed := httptest.NewRequest("GET", "/api", nil)
	allowed.RemoteAddr = "203.0.113.62:4711"
	router := ginlib.New()
	router.Use(secondGuard)
	router.Any("/*wildcard", func(c *ginlib.Context) {
		c.Status(http.StatusOK)
	})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, allowed)
	if rec.Code != 200 {
		t.Fatalf("unbanned IP must pass through the second engine, got %d", rec.Code)
	}
}
