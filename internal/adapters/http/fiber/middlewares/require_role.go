package middlewares

import (
	"github.com/gofiber/fiber/v2"
)

// RequireRole ensures the user has the required role (by name)
func RequireRole(requiredRoleName string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 1️⃣ Get roles from context (populated by JWTMiddleware)
		rolesRaw := c.Locals("roles")
		if rolesRaw == nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "access denied: no roles found",
			})
		}

		roles, ok := rolesRaw.([]string) // JWT stores role names as []string
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "access denied: invalid roles format",
			})
		}

		// 2️⃣ Check if the required role exists in the user's roles
		for _, r := range roles {
			if r == requiredRoleName {
				return c.Next()
			}
		}

		// 3️⃣ Access denied
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "access denied: insufficient permissions",
		})
	}
}
