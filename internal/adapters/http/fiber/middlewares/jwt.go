package middlewares

import (
	"errors"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func JWTMiddleware(
	tokenService aports.TokenServicePort,
	deviceRepo dports.DeviceRepositoryPort,
	uuidParser interfaces.IUUIDParserService,
) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return apperr.Unauthorized(errors.New("missing authorization header"))
		}

		// 1. TRANSPORT LOGIC: Header parsing
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return apperr.Unauthorized(errors.New("invalid token format"))
		}

		accessToken := parts[1]

		// 2. INFRASTRUCTURE: Token Validation
		// Note: tokenService already returns an apperr.Unauthorized from its implementation
		claims, err := tokenService.ValidateAccessToken(accessToken)
		if err != nil {
			return err
		}

		// 3. CROSS-LAYER CHECK: Device Usability
		deviceIDStr := claims.DeviceID
		if deviceIDStr != "" && deviceRepo != nil {
			deviceID, err := uuidParser.ParseDeviceID(deviceIDStr)
			if err != nil {
				// Parsing errors at this stage are validation issues
				return apperr.Validation(err)
			}

			device, err := deviceRepo.GetByID(deviceID)
			if err != nil {
				return apperr.Internal(err)
			}

			if device == nil {
				return apperr.Unauthorized(errors.New("device not recognized"))
			}

			// EnsureUsable returns a derr.DomainError (e.g., DeviceRevoked)
			// We wrap it in Unauthorized because a non-usable device invalidates the session
			if err := device.EnsureUsable(); err != nil {
				return apperr.Unauthorized(err)
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
