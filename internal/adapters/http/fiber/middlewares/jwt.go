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
			return apperr.NewUnauthorizedErr("missing authorization header")
		}

		// 1. TRANSPORT LOGIC: Header parsing
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return apperr.NewUnauthorizedErr("invalid token format")
		}

		accessToken := parts[1]

		// 2. INFRASTRUCTURE: Token Validation
		claims, err := tokenService.ValidateAccessToken(accessToken)
		if err != nil {
			return apperr.NewUnauthorizedErr("invalid or expired access token")
		}

		// 3. CROSS-LAYER CHECK: Device Usability
		deviceIDStr := claims.DeviceID
		if deviceIDStr != "" && deviceRepo != nil {
			deviceIDVO, err := valueobjects.DeviceIDFromString(deviceIDStr)
			if err != nil {
				return apperr.MapDomainErr(err)
			}

			device, err := deviceRepo.GetByID(deviceIDVO)
			if err != nil {
				return apperr.NewInternalErr("failed to verify device state")
			}

			if device == nil {
				return apperr.NewUnauthorizedErr("device not recognized")
			}

			if err := device.EnsureUsable(); err != nil {
				return apperr.MapDomainErr(err)
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
