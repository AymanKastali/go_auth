package fiberapp

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/requestid"
)

func SetupApp(handler *AuthHandler, middleware fiber.Handler, baseLogger *slog.Logger) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: NewErrorHandler(),
		AppName:      "AuthService v1.0",
	})
	app.Use(requestid.New())
	// app.Use(logger.New(logger.Config{
	// 	Format: logger.JSONFormat,
	// }))
	app.Use(logger.New(logger.Config{
		CustomTags: map[string]logger.LogFunc{
			// Define a custom tag "requestid" by calling Fiber's helper
			"requestid": func(out logger.Buffer, c fiber.Ctx, data *logger.Data, extra string) (int, error) {
				return out.WriteString(requestid.FromContext(c))
			},
		},
		// Use the custom tag in the format
		Format:     `{"time":"${time}", "ip":"${ip}", "req_id":"${requestid}", "method":"${method}", "url":"${url}", "status":${status}}` + "\n",
		TimeFormat: "2006-01-02T15:04:05.000Z07:00",
		TimeZone:   "UTC",
	}))

	// 2. Context middleware builds your RequestContext with scoped logger
	app.Use(ContextMiddleware(baseLogger))

	// 3. Error middleware (depends on RequestContext)
	app.Use(AppErrorMiddleware())

	// 4. Base API Group
	api := app.Group("/api/v1")

	// Public Routes
	auth := api.Group("/auth")
	auth.Post("/register", handler.Register)
	auth.Post("/login", handler.Login)
	auth.Post("/refresh", handler.Refresh)

	// Protected Routes
	protected := api.Group("/auth", middleware)
	protected.Post("/logout", handler.Logout)

	return app
}
