package fiberapp

import (
	"go_auth/internal/application"
	"go_auth/internal/domain"

	"github.com/gofiber/fiber/v3"
)

// RequireRole returns middleware that checks whether the authenticated user
// has at least one of the allowed roles.
func RequireRole(allowedRoles ...string) fiber.Handler {
	return func(c fiber.Ctx) error {
		roles := application.GetRoles(c.Context())
		for _, userRole := range roles {
			for _, allowed := range allowedRoles {
				if userRole == allowed {
					return c.Next()
				}
			}
		}
		return domain.ErrForbiddenRole
	}
}
