package fiberapp

import (
	"go_auth/internal/core/application"

	"github.com/gofiber/fiber/v3"
)

func Protected(validateUC application.IValidateAccessUseCase) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Now ExtractToken is defined and available
		token := ExtractToken(c.Get("Authorization"))
		if token == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "missing or invalid authorization header")
		}

		query := application.ValidateAccessQuery{
			AccessToken: token,
			Fingerprint: c.Get("X-Fingerprint"),
		}

		// access contains the validated UserID and SessionID
		access, err := validateUC.Execute(c.Context(), query)
		if err != nil {
			return err
		}

		// Inject IDs into Fiber locals
		c.Locals("user_id", access.UserID)
		c.Locals("session_id", access.SessionID)

		return c.Next()
	}
}
