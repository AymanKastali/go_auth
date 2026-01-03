package middlewares

import (
	"go_auth/internal/adapters/adaptererr"
	"go_auth/internal/core/application/apperr"
	services "go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/domain/ports/repositories"
	"go_auth/internal/core/domain/valueobjects"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func JWTMiddleware(
	tokenService services.TokenServicePort,
	deviceRepo repositories.DeviceRepositoryPort,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return respond(c, apperr.ErrUnauthorized)
		}

		// 1. TRANSPORT LOGIC: Header parsing
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return respond(c, apperr.ErrUnauthorized)
		}

		accessToken := parts[1]

		// 2. INFRASTRUCTURE: Token Validation
		claims, err := tokenService.ValidateAccessToken(accessToken)
		if err != nil {
			// If the token is cryptographically dead, we treat it as an App Unauthorized error
			return respond(c, apperr.ErrUnauthorized)
		}

		// 3. CROSS-LAYER CHECK: Device Usability
		deviceIDStr := claims.DeviceID
		if deviceIDStr != "" && deviceRepo != nil {

			// DOMAIN: Parse Value Object
			deviceIDVO, err := valueobjects.DeviceIDFromString(deviceIDStr)
			if err != nil {
				// Map domain-specific parse error via apperr firewall
				return respond(c, apperr.MapDomain(err))
			}

			// INFRASTRUCTURE: DB Retrieval
			device, err := deviceRepo.GetByID(deviceIDVO)
			if err != nil {
				return respond(c, apperr.ErrInternal)
			}

			if device == nil {
				return respond(c, apperr.ErrDeviceNotFound)
			}

			// DOMAIN: Business Rule check
			if err := device.EnsureUsable(); err != nil {
				// Map domain violation (e.g., CodeRuleViolation)
				return respond(c, apperr.MapDomain(err))
			}
		}

		// 4. CONTEXT SETTING
		c.Locals("sub", claims.Subject)
		c.Locals("roles", claims.Roles)
		c.Locals("jti", claims.JTI)
		c.Locals("deviceID", deviceIDStr)

		return c.Next()
	}
}

// respond is the adapter-layer helper that translates errors into Fiber responses.
func respond(c *fiber.Ctx, err error) error {
	// Translate is the single source of truth for HTTP codes and JSON structure
	status, payload := adaptererr.Translate(err)
	return c.Status(status).JSON(payload)
}
