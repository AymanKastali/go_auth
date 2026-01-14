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
	// 1. Get RequestID from Fiber context (assuming you use the RequestID middleware)
	// If not found, it defaults to an empty string or a fallback.
	requestID := c.GetRespHeader(fiber.HeaderXRequestID, "00000000-0000-0000-0000-000000000000")

	// Default fallback values
	statusCode := http.StatusInternalServerError
	resp := fiber.Map{
		"success":    false,
		"message":    "An unexpected server error occurred",
		"code":       derr.CodeInternal,
		"request_id": requestID, 
	}

	// 2. Check if it's our custom AppError interface
	var aErr apperr.AppError
	if errors.As(err, &aErr) {
		switch aErr.Code() {
		case derr.CodeValidation:
			statusCode = http.StatusBadRequest
		case derr.CodeNotFound:
			statusCode = http.StatusNotFound
		case derr.CodeConflict:
			statusCode = http.StatusConflict
		case derr.CodePermissionDenied:
			statusCode = http.StatusForbidden
		case derr.CodeInternal:
			statusCode = http.StatusInternalServerError
		}

		resp["message"] = aErr.Error()
		resp["code"] = aErr.Code()
		
		// Use the TraceID from the error if available, otherwise fallback to context ID
		if aErr.TraceID() != "" {
			resp["request_id"] = aErr.TraceID()
		}

		// Log based on severity
		if aErr.Code() == derr.CodeInternal {
			slog.Error("Internal Application Error",
				"path", c.Path(),
				"request_id", resp["request_id"],
				"cause", aErr.Cause(),
				"error", aErr.Error(),
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

	// 3. Handle Fiber specific errors (e.g. 404 on invalid routes)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		statusCode = fiberErr.Code
		resp["message"] = fiberErr.Message
		resp["code"] = "FIBER_ERROR" // Or a specific derr mapping
		return c.Status(statusCode).JSON(resp)
	}

	// 4. Final Fallback for unhandled technical errors (e.g. library panics)
	slog.Error("Unhandled Technical Error", 
		"path", c.Path(), 
		"request_id", requestID,
		"error", err.Error(),
	)
	
	return c.Status(statusCode).JSON(resp)
}