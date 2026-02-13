package fiberapp

import (
	"go_auth/internal/application"
	"go_auth/internal/application/query"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v3"
)

func Protected(validateAccess query.IValidateAccessHandler) fiber.Handler {
	return func(c fiber.Ctx) error {
		logger := application.GetLogger(c.Context())

		token := extractToken(c.Get("Authorization"))
		if token == "" {
			logger.Warn("authorization_attempt_missing_token")
			return fiber.NewError(fiber.StatusUnauthorized, "missing authorization header")
		}

		access, err := validateAccess.Handle(c.Context(), query.ValidateAccessQuery{
			AccessToken: token,
			Fingerprint: c.Get("X-Fingerprint"),
		})
		if err != nil {
			return err
		}

		rc, err := FromContext(c.Context())
		if err != nil {
			logger.Error("context_lost_during_protection_middleware")
			return err
		}

		if err := rc.AttachUser(access.UserID, access.SessionID, access.Roles); err != nil {
			logger.Error("failed_to_attach_user_to_context", slog.Any("error", err))
			return err
		}

		c.SetContext(application.WithAppContext(c.Context(), rc.AppContext()))

		return c.Next()
	}
}

// Bearer Token
func extractToken(authHeader string) string {
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}
