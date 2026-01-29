package fiberapp

import (
	"errors"
	"log/slog"
	"strings"

	"go_auth/internal/core/application"
	"go_auth/internal/core/pkg/err"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
)

// Go Validator
var validate = validator.New()

func Validate(data any) error { return validate.Struct(data) }

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

// Error Utils
func logRequestError(c fiber.Ctx, status int, e error) {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	// Default values for standard errors
	logLv := slog.LevelWarn
	appCode := "INTERNAL_ERROR"

	// Check if it's a domain error to extract more specific metadata
	var appErr *err.Error
	if errors.As(e, &appErr) {
		appCode = string(appErr.Code())
	}

	if status >= 500 {
		logLv = slog.LevelError
	}

	logger.Log(ctx, logLv, "http_request_handled_with_error",
		slog.Int("status", status),
		slog.String("app_code", appCode),
		slog.String("method", c.Method()),
		slog.String("path", c.Path()),
		slog.String("ip", c.IP()),
		slog.String("err_detail", e.Error()), // Log the actual error string
	)
}

func mapCodeToHTTPStatus(code err.Code) int {
	switch code {
	case err.CodeValidation:
		return fiber.StatusUnprocessableEntity
	case err.CodeUnauthorized:
		return fiber.StatusUnauthorized
	case err.CodeForbidden:
		return fiber.StatusForbidden
	case err.CodeNotFound:
		return fiber.StatusNotFound
	case err.CodeConflict:
		return fiber.StatusConflict
	case err.CodeBusinessRule:
		return fiber.StatusUnprocessableEntity
	default:
		return fiber.StatusInternalServerError
	}
}
