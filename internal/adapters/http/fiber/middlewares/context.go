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
		requestID := requestid.FromContext(c)

		// 1. Collect raw traits into a map
		// This is what the Hasher in the Application layer will process
		traits := map[string]string{
			"ua":  c.Get("User-Agent"),
			"cpu": c.Get("X-Device-CPU"),
			"mem": c.Get("X-Device-Memory"),
			"res": c.Get("X-Device-Screen"),
		}

		reqCtx := &utils.RequestContext{
			RequestID:         requestID,
			DeviceFingerprint: traits, // Now a map[string]string
			DeviceName:        c.Get("X-Device-Name"),
			UserAgent:         c.Get("User-Agent"),
			IPAddress:         c.IP(),
		}

		// 2. Logger (Note: You can't log the whole map easily, maybe just the UA or a summary)
		reqCtx.Logger = l.With(
			slog.String("trace_id", reqCtx.RequestID),
			slog.String("ip", reqCtx.IPAddress),
		)

		// 3. Inject into Fiber Locals
		c.Locals(FiberCtxKey, reqCtx)

		// 4. Inject into Standard Context
		c.SetContext(utils.WithRequest(c.Context(), reqCtx))

		return c.Next()
	}
}
