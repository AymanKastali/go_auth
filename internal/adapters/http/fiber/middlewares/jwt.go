package middlewares

import (
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
			return apperr.NewUnauthorized("missing authorization header")
		}

		// 1. TRANSPORT LOGIC: Header parsing
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return apperr.NewUnauthorized("invalid token format")
		}

		accessToken := parts[1]

		// 2. INFRASTRUCTURE: Token Validation
		claims, err := tokenService.ValidateAccessToken(accessToken)
		if err != nil {
			return apperr.NewUnauthorized("invalid or expired access token")
		}

		// 3. CROSS-LAYER CHECK: Device Usability
		deviceIDStr := claims.DeviceID
		if deviceIDStr != "" && deviceRepo != nil {
			deviceIDVO, err := valueobjects.DeviceIDFromString(deviceIDStr)
			if err != nil {
				return apperr.MapDomain(err)
			}

			device, err := deviceRepo.GetByID(deviceIDVO)
			if err != nil {
				return apperr.NewInternal("failed to verify device state")
			}

			if device == nil {
				return apperr.NewUnauthorized("device not recognized")
			}

			if err := device.EnsureUsable(); err != nil {
				return apperr.MapDomain(err)
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
