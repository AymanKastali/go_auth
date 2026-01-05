package middlewares

import (
	"go_auth/internal/core/application/apperr"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func RequireRole(requiredRoleName string) fiber.Handler {
	required := strings.ToLower(requiredRoleName)

	return func(c *fiber.Ctx) error {
		rolesRaw := c.Locals("roles")
		if rolesRaw == nil {
			return apperr.NewUnauthorizedErr("no session found")
		}

		roles, ok := rolesRaw.([]string)
		if !ok {
			return apperr.NewInternalErr("invalid session data")
		}

		// Normalize roles
		for i := range roles {
			roles[i] = strings.ToLower(roles[i])
		}

		if slices.Contains(roles, required) {
			return c.Next()
		}

		return apperr.NewForbiddenErr("insufficient permissions")
	}
}
