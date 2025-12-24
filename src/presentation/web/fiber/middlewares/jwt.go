package middlewares

import (
	services "go_auth/src/application/ports/security"
	"go_auth/src/domain/errors"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// JWTMiddleware validates access tokens and checks device revocation.
func JWTMiddleware(
	tokenService services.TokenServicePort,
	deviceRepo repositories.DeviceRepositoryPort,
	idFactory factories.IDFactory,
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
		deviceIdStr := claims.DeviceId
		if deviceIdStr != "" && deviceRepo != nil {
			deviceIdVo, err := idFactory.DeviceIDFromString(deviceIdStr)
			if err != nil {
				return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "invalid device id",
				})
			}

			device, err := deviceRepo.GetByID(deviceIdVo)
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
				case errors.ErrDeviceRevoked:
					return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "device revoked",
					})
				case errors.ErrDeviceInactive:
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
		ctx.Locals("deviceID", deviceIdStr)

		return ctx.Next()
	}
}
