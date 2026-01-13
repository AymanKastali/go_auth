package middlewares

import (
	"errors"
	"fmt" // Added for printing
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
		fmt.Printf("\n--- [Auth Middleware] %s %s ---\n", c.Method(), c.Path())

		// 1. TRANSPORT VALIDATION: Check if header exists
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			fmt.Println("[Auth] Missing header -> 400 Validation")
			return apperr.Validation(errors.New("authorization header is required"))
		}

		// 2. PROTOCOL VALIDATION: Check Bearer format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			fmt.Println("[Auth] Malformed header format -> 400 Validation")
			return apperr.Validation(errors.New("invalid authorization format (expected Bearer <token>)"))
		}

		accessToken := parts[1]
		if accessToken == "" {
			fmt.Println("[Auth] Empty token string -> 400 Validation")
			return apperr.Validation(errors.New("token cannot be empty"))
		}

		// 3. SECURITY SERVICE: Validate Token Identity
		// This call handles the heavy lifting (Signatures, Expiration, Claims)
		claims, err := tokenService.ValidateAccessToken(accessToken)
		if err != nil {
			fmt.Printf("[Auth] Identity rejected: %v -> 401 Unauthorized\n", err)
			// Any failure here means the identity is not trusted/proven
			return apperr.Unauthorized(err)
		}

		// 4. DOMAIN POLICY: Check Device/Session State
		deviceIDStr := claims.DeviceID
		if deviceIDStr != "" && deviceRepo != nil {
			deviceID, err := uuidParser.ParseDeviceID(deviceIDStr)
			if err != nil {
				fmt.Printf("[Auth] DeviceID parsing error: %v\n", err)
				return apperr.Validation(err)
			}

			device, err := deviceRepo.GetByID(deviceID)
			if err != nil {
				fmt.Printf("[Auth] Repository Error: %v\n", err)
				return apperr.Internal(err)
			}

			// If token has a deviceID but device doesn't exist or is unusable
			if device == nil {
				fmt.Println("[Auth] Device not found -> 401 Unauthorized")
				return apperr.Unauthorized(errors.New("session device not recognized"))
			}

			if err := device.EnsureUsable(); err != nil {
				fmt.Printf("[Auth] Device policy violation: %v -> 401 Unauthorized\n", err)
				return apperr.Unauthorized(err)
			}
		}

		// 5. CONTEXT PROPAGATION: Set values for handlers
		c.Locals("sub", claims.Subject)
		c.Locals("roles", claims.Roles)
		c.Locals("jti", claims.JTI)
		c.Locals("deviceID", deviceIDStr)

		fmt.Printf("[Auth] Success. Subject: %s\n", claims.Subject)
		return c.Next()
	}
}
