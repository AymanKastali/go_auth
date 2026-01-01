package middlewares

import (
	"go_auth/internal/core/application/apperr"
	services "go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/domain/ports/repositories"
	"go_auth/internal/core/domain/valueobjects"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// JWTMiddleware validates access tokens and checks device usability.
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
				"error": apperr.ErrInvalidCredentials.Error(),
			})
		}

		// 2. Check if the device is usable
		deviceIDStr := claims.DeviceID
		if deviceIDStr != "" && deviceRepo != nil {
			deviceIDVO, err := valueobjects.DeviceIDFromString(deviceIDStr)
			if err != nil {
				return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": apperr.FromDomainError(err),
				})
			}

			device, err := deviceRepo.GetByID(deviceIDVO)
			if err != nil {
				return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": apperr.ErrInternal.Error(),
				})
			}

			if device == nil {
				return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": apperr.ErrDeviceNotFound.Error(),
				})
			}

			if err := device.EnsureUsable(); err != nil {
				appErr := apperr.FromDomainError(err)
				return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": appErr.Error(),
				})
			}
		}

		// 3. Store user info in context for downstream handlers
		ctx.Locals("sub", claims.Subject)
		ctx.Locals("roles", claims.Roles)
		ctx.Locals("jti", claims.JTI)
		ctx.Locals("deviceID", deviceIDStr)

		return ctx.Next()
	}
}
