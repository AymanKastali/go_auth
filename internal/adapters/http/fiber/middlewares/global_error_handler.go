package middlewares

import (
	"errors"
	"go_auth/internal/core/application/apperr"
	"log/slog"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func GlobalErrorHandler(c *fiber.Ctx, err error) error {
	// Default values
	code := http.StatusInternalServerError
	resp := fiber.Map{
		"success": false,
		"type":    apperr.TypeInternal,
		"message": "An unexpected server error occurred",
	}

	var appErr *apperr.AppError

	if errors.As(err, &appErr) {
		// Map Application Intent to HTTP Status
		switch appErr.Type {
		case apperr.TypeValidation, apperr.TypeRequirement:
			code = http.StatusBadRequest
		case apperr.TypeUnauthorized:
			code = http.StatusUnauthorized
		case apperr.TypeForbidden:
			code = http.StatusForbidden
		case apperr.TypeNotFound:
			code = http.StatusNotFound
		case apperr.TypeConflict:
			code = http.StatusConflict
		case apperr.TypeInternal:
			code = http.StatusInternalServerError
		}

		resp["type"] = appErr.Type
		resp["message"] = appErr.Message
		if appErr.Key != "" {
			resp["key"] = appErr.Key
		}

		// Log critical internal failures
		if appErr.Type == apperr.TypeInternal {
			slog.Error("Internal Error", "path", c.Path(), "cause", appErr.Cause)
		}

	} else {
		// Handle non-AppErrors (e.g., Fiber's 404 for undefined routes)
		var fiberErr *fiber.Error
		if errors.As(err, &fiberErr) {
			code = fiberErr.Code
			resp["type"] = "TRANSPORT_ERROR"
			resp["message"] = fiberErr.Message
		} else {
			slog.Warn("Unhandled technical error", "path", c.Path(), "error", err.Error())
		}
	}

	return c.Status(code).JSON(resp)
}
