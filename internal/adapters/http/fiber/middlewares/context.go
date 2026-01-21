package middlewares

import (
	"go_auth/internal/core/application/dto"
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

const FiberCtxKey = "app_context"

func NewContextMiddleware(l *slog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. Extract Identity
		requestID, _ := c.Locals("requestid").(string)
		deviceFingerprint := c.Get("X-Device-Fingerprint")

		// 2. Scoped Logger (Tracing is now automatic)
		reqLogger := l.With(
			slog.String("trace_id", requestID),
			slog.String("fingerprint", deviceFingerprint),
		)

		reqCtx := &dto.RequestContext{
			RequestID:         requestID,
			DeviceFingerprint: deviceFingerprint,
			DeviceName:        c.Get("X-Device-Name"),
			UserAgent:         c.Get("User-Agent"),
			IPAddress:         c.IP(),
			Logger:            reqLogger,
		}

		// 3. Inject into Fiber Locals
		c.Locals(FiberCtxKey, reqCtx)

		// 4. Inject into Standard Context (Crucial for Services)
		c.SetUserContext(dto.Inject(c.UserContext(), reqCtx))

		return c.Next()
	}
}
