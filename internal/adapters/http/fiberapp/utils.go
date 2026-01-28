package fiberapp

import (
	"strings"

	"go_auth/internal/core/application"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
)

// Go Validator
var validate = validator.New()

func Validate(s any) error { return validate.Struct(s) }

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

// Map To Status Error
func mapAppErrorToStatus(code application.AppErrorCode) int {
	switch code {
	case application.AppErrUnprocessable:
		return fiber.StatusUnprocessableEntity
	case application.AppErrUnauthorized:
		return fiber.StatusUnauthorized
	case application.AppErrForbidden:
		return fiber.StatusForbidden
	case application.AppErrNotFound:
		return fiber.StatusNotFound
	case application.AppErrConflict:
		return fiber.StatusConflict
	case application.AppErrInternal:
		return fiber.StatusInternalServerError
	default:
		return fiber.StatusInternalServerError
	}
}
