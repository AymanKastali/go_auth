package middlewares

import (
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
		// 1. TraceID Extraction (Crucial for our new error system)
		// We assume a RequestID middleware ran before this, or we generate one.
		traceID := c.Get("X-Request-ID")
		if traceID == "" {
			traceID = "system-middleware"
		}

		// 2. Transport Validation
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return apperr.BadRequest("authorization header is required", traceID, nil)
		}

		// 3. Protocol Validation
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return apperr.BadRequest("invalid authorization format", traceID, nil)
		}

		accessToken := parts[1]
		if accessToken == "" {
			return apperr.BadRequest("token cannot be empty", traceID, nil)
		}

		// 4. Security Service: Validate Token Identity
		// tokenService.ValidateAccessToken returns derr.DomainError
		claims, err := tokenService.ValidateAccessToken(accessToken)
		if err != nil {
			// Maps derr.ErrExpired or derr.ErrInvalid to AppError
			return apperr.FromDomain(err, traceID)
		}

		// 5. Domain Policy: Check Device/Session State
		deviceIDStr := claims.DeviceID
		if deviceIDStr != "" && deviceRepo != nil {
			deviceID, err := uuidParser.ParseDeviceID(deviceIDStr)
			if err != nil {
				return apperr.BadRequest("malformed device id in token", traceID, err)
			}

			device, err := deviceRepo.GetByID(deviceID)
			if err != nil {
				return apperr.FromDomain(err, traceID)
			}

			// Device must exist in our system
			if device == nil {
				return apperr.Unauthorized("session device not recognized", traceID, nil)
			}

			// Check if device is Revoked or Inactive (Domain Logic)
			if err := device.EnsureUsable(); err != nil {
				return apperr.FromDomain(err, traceID)
			}
		}

		// 6. Context Propagation
		c.Locals("sub", claims.Subject)
		c.Locals("roles", claims.Roles)
		c.Locals("jti", claims.JTI)
		c.Locals("deviceID", deviceIDStr)
		c.Locals("trace_id", traceID)

		return c.Next()
	}
}
