package middlewares

import (
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v3"
)

func RequireRole(requiredRoleName string) fiber.Handler {
	required := strings.ToUpper(requiredRoleName)

	return func(c fiber.Ctx) error {
		// 1. Extract AuthContext directly from the standard context
		auth, ok := utils.AuthFromContext(c.Context())
		if !ok {
			// We use the universal getter to at least get a Logger/TraceID
			// for the warning log even if auth failed
			utils.FromContext(c.Context()).Logger.Warn("Role check failed: no authenticated session found")
			return apperr.Unauthorized("authentication session not found", nil)
		}

		// Use the enriched logger (which already has user_id/trace_id)
		l := auth.Logger

		// 2. Perform Role Check
		hasRole := false
		for _, r := range auth.Roles {
			if strings.ToUpper(r) == required {
				hasRole = true
				break
			}
		}

		if !hasRole {
			l.Warn("Access denied: insufficient permissions",
				slog.String("required_role", required),
				slog.Any("user_roles", auth.Roles),
			)
			return apperr.Forbidden("insufficient permissions to access this resource", nil)
		}

		l.Debug("Role authorization successful", slog.String("role", required))
		return c.Next()
	}
}
