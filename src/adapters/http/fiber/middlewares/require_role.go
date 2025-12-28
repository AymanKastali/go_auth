package middlewares

import (
	"go_auth/src/domain/value_objects"

	"github.com/gofiber/fiber/v2"
)

func RequireRole(requiredRole value_objects.Role) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1. Get roles from context (populated by JWTMiddleware)
		rolesRaw := c.Locals("roles")
		roles, ok := rolesRaw.([]string) // Adjust type if your claims use []value_objects.Role
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "access denied: no roles found",
			})
		}

		// 2. Check if the required role exists in the user's roles
		hasRole := false
		for _, r := range roles {
			if r == string(requiredRole) {
				hasRole = true
				break
			}
		}

		if !hasRole {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "access denied: insufficient permissions",
			})
		}

		return c.Next()
	}
}
