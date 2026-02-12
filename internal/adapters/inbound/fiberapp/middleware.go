package fiberapp

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
)

// IIDGenerator defines the contract for generating trace/request IDs.
// This is an adapter-layer concern — no handler depends on it.
type IIDGenerator interface {
	Generate() (string, error)
}

func ConfigureMiddlewares(app *fiber.App, baseLogger *slog.Logger, idGen IIDGenerator) {
	// 1. Panic Recovery — catch panics and convert to errors
	app.Use(recover.New())

	// 2. Trace ID / Request ID
	app.Use(requestid.New(requestid.Config{
		Generator: func() string {
			id, _ := idGen.Generate()
			return id
		},
	}))

	// 3. Access Logging
	app.Use(logger.New(logger.Config{
		Format:     `{"time":"${time}", "ip":"${ip}", "req_id":"${respHeader:X-Request-ID}", "method":"${method}", "url":"${url}", "status":${status}}` + "\n",
		TimeFormat: "2006-01-02T15:04:05.000Z",
		TimeZone:   "UTC",
	}))

	// 4. Domain Context & Error Handling
	app.Use(ContextMiddleware(baseLogger))
}
