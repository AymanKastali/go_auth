package middlewares

import (
	services "go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/domain/domainerr"
	"go_auth/internal/core/domain/ports/repositories"
	"go_auth/internal/core/domain/valueobjects"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// JWTMiddleware validates access tokens and checks device revocation.
func JWTMiddleware(
	tokenService services.TokenServicePort,
	deviceRepo repositories.DeviceRepositoryPort,
) fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		authHeader := ctx.Get("Authorization")
		if authHeader == "" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing access token",
			})
		}

		// Expect "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid authorization header",
			})
		}

		accessToken := parts[1]

		// 1. Validate access token cryptographically
		claims, err := tokenService.ValidateAccessToken(accessToken)
		if err != nil {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired token",
			})
		}

		// 2. Check if the device is revoked
		deviceIDStr := claims.DeviceID
		if deviceIDStr != "" && deviceRepo != nil {
			deviceIDVO, err := valueobjects.DeviceIDFromString(deviceIDStr)
			if err != nil {
				return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "invalid device id",
				})
			}

			device, err := deviceRepo.GetByID(deviceIDVO)
			if err != nil {
				return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "failed to validate device",
				})
			}

			if device == nil {
				return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "device not found",
				})
			}

			if err := device.EnsureUsable(); err != nil {
				switch err {
				case domainerr.ErrDeviceRevoked:
					return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "device revoked",
					})
				case domainerr.ErrDeviceInactive:
					return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "device inactive",
					})
				default:
					return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "invalid device",
					})
				}
			}
		}

		// 3. Store user info in context
		ctx.Locals("sub", claims.Subject)
		ctx.Locals("roles", claims.Roles)
		ctx.Locals("jti", claims.JTI)
		ctx.Locals("deviceID", deviceIDStr)

		return ctx.Next()
	}
}
