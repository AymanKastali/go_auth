package middlewares

import (
	"go_auth/internal/adapters/http/fiber/utils"
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"
)

const FiberCtxKey = "app_context"

func NewContextMiddleware(l *slog.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		// 1. Extract Identity
		requestID := requestid.FromContext(c)

		reqCtx := &utils.RequestContext{
			RequestID:         requestID,
			DeviceFingerprint: c.Get("X-Device-Fingerprint"),
			DeviceName:        c.Get("X-Device-Name"),
			UserAgent:         c.Get("User-Agent"),
			IPAddress:         c.IP(),
		}

		reqCtx.Logger = l.With(
			slog.String("trace_id", reqCtx.RequestID),
			slog.String("fingerprint", reqCtx.DeviceFingerprint),
			slog.String("ip", reqCtx.IPAddress),
		)

		// 3. Inject into Fiber Locals
		c.Locals(FiberCtxKey, reqCtx)

		// 4. Inject into Standard Context (Crucial for Services)
		newStdCtx := utils.WithRequest(c.Context(), reqCtx)
		c.SetContext(newStdCtx)

		return c.Next()
	}
}
