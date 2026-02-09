package fiberapp

import (
	"go_auth/internal/application"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v3"
)

func Protected(validateUC application.IValidateAccessUseCase) fiber.Handler {
	return func(c fiber.Ctx) error {
		logger := application.GetLogger(c.Context())

		token := extractToken(c.Get("Authorization"))
		if token == "" {
			logger.Warn("authorization_attempt_missing_token")
			return fiber.NewError(fiber.StatusUnauthorized, "missing authorization header")
		}

		access, err := validateUC.Execute(c.Context(), application.ValidateAccessQuery{
			AccessToken: token,
			Fingerprint: c.Get("X-Fingerprint"),
		})
		if err != nil {
			// UseCase already logs internal details, so we just return
			return err
		}

		rc, err := FromContext(c.Context())
		if err != nil {
			logger.Error("context_lost_during_protection_middleware")
			return err
		}

		if err := rc.AttachUser(access.UserID, access.SessionID); err != nil {
			logger.Error("failed_to_attach_user_to_context", slog.Any("error", err))
			return err
		}

		c.SetContext(application.WithAppContext(c.Context(), rc.AppContext()))

		logger.Debug("request_authenticated", slog.String("user_id", access.UserID))
		return c.Next()
	}
}

// Bearer Token
func extractToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}

	// Standard Bearer token format: "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		// If it doesn't follow Bearer format, return as is or return empty
		// depending on your strictness. Here we stay strict:
		return ""
	}

	return parts[1]
}
