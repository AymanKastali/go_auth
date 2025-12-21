package middlewares

import (
	services "go_auth/src/application/ports/security"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func JWTMiddleware(tokenService services.TokenServicePort) fiber.Handler {
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

		claims, err := tokenService.ValidateAccessToken(parts[1])
		if err != nil {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired token",
			})
		}

		// Store user ID in context
		ctx.Locals("userID", claims.UserID)

		return ctx.Next()
	}
}
