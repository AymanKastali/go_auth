package middlewares

import (
	"go_auth/internal/core/application/apperr"
	"slices"

	"github.com/gofiber/fiber/v2"
)

func RequireRole(requiredRoleName string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. Adapter logic: Extract data from the Web Context
		rolesRaw := c.Locals("roles")
		if rolesRaw == nil {
			// Mapping a Web failure to an Application Error
			return apperr.NewUnauthorizedErr("no session found")
		}

		roles, ok := rolesRaw.([]string)
		if !ok {
			return apperr.NewInternalErr("invalid session data")
		}

		// 2. Application/Business Logic: Does the user meet the criteria?
		if slices.Contains(roles, requiredRoleName) {
			return c.Next()
		}

		// 3. Application Error: Access Denied
		return apperr.NewForbiddenErr("insufficient permissions")
	}
}
