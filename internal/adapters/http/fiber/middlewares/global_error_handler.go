package middlewares

import (
	"errors"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/derr"
	"log/slog"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func GlobalErrorHandler(c *fiber.Ctx, err error) error {
	// 1. Default fallback values
	statusCode := http.StatusInternalServerError
	resp := fiber.Map{
		"success":  false,
		"message":  "An unexpected server error occurred",
		"code":     derr.CodeInternal,
		"trace_id": "00000000-0000-0000-0000-000000000000",
	}

	// 2. Check if it's our custom AppError interface
	var aErr apperr.AppError
	if errors.As(err, &aErr) {
		// Map our Domain/App Codes to HTTP Status Codes
		switch aErr.Code() {
		case derr.CodeValidation:
			statusCode = http.StatusBadRequest
		case derr.CodeNotFound:
			statusCode = http.StatusNotFound
		case derr.CodeConflict:
			statusCode = http.StatusConflict
		case derr.CodePermissionDenied:
			// Logic: We can further distinguish 401 vs 403 based on message if needed,
			// but usually CodePermissionDenied maps to 403 or 401.
			statusCode = http.StatusForbidden
		case derr.CodeInternal:
			statusCode = http.StatusInternalServerError
		}

		resp["message"] = aErr.Error()
		resp["code"] = aErr.Code()
		resp["trace_id"] = aErr.TraceID()

		// Log the internal cause for 500 errors
		if aErr.Code() == derr.CodeInternal {
			slog.Error("Internal Application Error",
				"path", c.Path(),
				"trace_id", aErr.TraceID(),
				"cause", aErr.Cause(),
			)
		} else {
			slog.Warn("Business Rule Violation",
				"path", c.Path(),
				"code", aErr.Code(),
				"message", aErr.Error(),
			)
		}

		return c.Status(statusCode).JSON(resp)
	}

	// 3. Handle Fiber specific errors (e.g. 404 Not Found on routes)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		return c.Status(fiberErr.Code).JSON(fiber.Map{
			"success": false,
			"message": fiberErr.Message,
			"code":    derr.CodeUnknown,
		})
	}

	// 4. Final Fallback for unhandled technical errors
	slog.Error("Unhandled Technical Error", "path", c.Path(), "error", err.Error())
	return c.Status(statusCode).JSON(resp)
}
