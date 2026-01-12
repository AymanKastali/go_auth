package middlewares

import (
	"errors"
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
			// If no roles are found, the session is essentially invalid/missing
			return apperr.Unauthorized(errors.New("no session found"))
		}

		roles, ok := rolesRaw.([]string)
		if !ok {
			// This represents a developer error or a state corruption in locals
			return apperr.Internal(errors.New("invalid session data format"))
		}

		// Normalize roles for comparison
		normalizedRoles := make([]string, len(roles))
		for i, r := range roles {
			normalizedRoles[i] = strings.ToLower(r)
		}

		if slices.Contains(normalizedRoles, required) {
			return c.Next()
		}

		// Use the Forbidden intent for authenticated users with insufficient roles
		return apperr.Forbidden(errors.New("insufficient permissions to access this resource"))
	}
}
