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
		// 1. Extract TraceID (passed from JWTMiddleware or RequestID middleware)
		traceID, _ := c.Locals("trace_id").(string)
		if traceID == "" {
			traceID = "system-rbac"
		}

		// 2. Retrieve Roles from Context
		rolesRaw := c.Locals("roles")
		if rolesRaw == nil {
			// If no roles are found, the user isn't authenticated or the middleware order is wrong
			return apperr.Unauthorized("authentication session not found", traceID, nil)
		}

		roles, ok := rolesRaw.([]string)
		if !ok {
			// Technical failure: the data type in Locals is corrupted
			return apperr.Internal("integrity failure: invalid role data format", traceID, nil)
		}

		// 3. Normalize roles for case-insensitive comparison
		normalizedRoles := make([]string, len(roles))
		for i, r := range roles {
			normalizedRoles[i] = strings.ToLower(r)
		}

		// 4. Authorization Logic
		if slices.Contains(normalizedRoles, required) {
			return c.Next()
		}

		// 5. Explicit Permission Denied
		// This results in a 403 Forbidden via the GlobalErrorHandler
		return apperr.Forbidden("insufficient permissions to access this resource", traceID, nil)
	}
}
