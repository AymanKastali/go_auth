package fiberapp

import (
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
)

// IIDGenerator defines the contract for generating trace/request IDs.
// This is an adapter-layer concern — no handler depends on it.
type IIDGenerator interface {
	Generate() (string, error)
}

func ConfigureMiddlewares(app *fiber.App, baseLogger *slog.Logger, idGen IIDGenerator, corsOrigins []string) {
	// 1. Panic Recovery — catch panics and convert to errors
	app.Use(recover.New())

	// 2. Security Headers
	app.Use(SecurityHeaders())

	// 3. CORS — AllowCredentials is only valid with explicit origins, not "*".
	hasWildcard := len(corsOrigins) == 1 && corsOrigins[0] == "*"
	app.Use(cors.New(cors.Config{
		AllowOrigins:     corsOrigins,
		AllowMethods:     []string{"GET", "POST", "PATCH", "DELETE"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		AllowCredentials: !hasWildcard,
	}))

	// 4. Trace ID / Request ID
	app.Use(requestid.New(requestid.Config{
		Generator: func() string {
			id, _ := idGen.Generate()
			return id
		},
	}))

	// 5. Access Logging
	app.Use(logger.New(logger.Config{
		Format:     `{"time":"${time}", "ip":"${ip}", "req_id":"${respHeader:X-Request-ID}", "method":"${method}", "url":"${url}", "status":${status}}` + "\n",
		TimeFormat: "2006-01-02T15:04:05.000Z",
		TimeZone:   "UTC",
	}))

	// 6. Domain Context & Error Handling
	app.Use(ContextMiddleware(baseLogger))
}

// SecurityHeaders returns a middleware that sets common security response headers.
func SecurityHeaders() fiber.Handler {
	return func(c fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-XSS-Protection", "0")
		c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Set("Content-Security-Policy", "default-src 'none'")
		c.Set("Referrer-Policy", "no-referrer")
		return c.Next()
	}
}

// NewAuthRateLimiter returns a rate limiting middleware for auth endpoints.
func NewAuthRateLimiter() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:        20,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "too many requests, please try again later",
			})
		},
	})
}
