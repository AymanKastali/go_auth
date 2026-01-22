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
		reqCtx := utils.ReqCtx(c)
		l := reqCtx.Logger

		auth, ok := utils.AuthCtx(c)
		if !ok {
			l.Warn("Role check failed: no authenticated session found")
			return apperr.Unauthorized("authentication session not found", nil)
		}

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
