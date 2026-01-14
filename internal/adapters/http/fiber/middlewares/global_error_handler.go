package middlewares

import (
	"errors"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/core/application/apperr"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func GlobalErrorHandler(c *fiber.Ctx, err error) error {
	if err == nil {
		return nil
	}

	requestID, _ := c.Locals("request_id").(string)
	if requestID == "" {
		requestID = "00000000-0000-0000-0000-000000000000"
	}

	// Default initialization
	statusCode := http.StatusInternalServerError
	resp := dto.ErrorResponse{
		Success: false,
		Kind:    int(apperr.KindInternal), // Default to internal kind
		Message: "An unexpected server error occurred",
	}

	var aErr *apperr.AppError
	if errors.As(err, &aErr) {
		if aErr.RequestID != "" {
			requestID = aErr.RequestID
		}

		// 1. Map Application Kind to HTTP Status
		switch aErr.Kind {
		case apperr.KindInvalid:
			statusCode = http.StatusBadRequest
		case apperr.KindUnauthenticated:
			statusCode = http.StatusUnauthorized
		case apperr.KindUnauthorized:
			statusCode = http.StatusForbidden
		case apperr.KindNotFound:
			statusCode = http.StatusNotFound
		case apperr.KindConflict:
			statusCode = http.StatusConflict
		case apperr.KindInternal:
			statusCode = http.StatusInternalServerError
		}

		// 2. Build Response
		resp.Kind = int(aErr.Kind)
		resp.Message = aErr.Message

		// 3. Handle Validation Details (Field extraction)
		if aErr.Kind == apperr.KindInvalid && aErr.Err != nil {
			errMsg := aErr.Err.Error()
			resp.Message = errMsg

			// Simple logic to extract field name from common validation strings
			// e.g., "Key: 'LoginRequest.Email' Error:Field validation..."
			if strings.Contains(errMsg, "Key: '") {
				start := strings.Index(errMsg, ".") + 1
				end := strings.Index(errMsg, "'")
				if start > 0 && end > start {
					resp.Field = errMsg[start:end]
				}
			}
		}

		// 4. Log based on severity
		if aErr.Kind == apperr.KindInternal {
			slog.Error("Internal Failure", "path", c.Path(), "request_id", requestID, "error", aErr.Err)
		} else {
			slog.Warn("Business Logic Blocked", "path", c.Path(), "kind", resp.Kind, "message", resp.Message)
		}

		return c.Status(statusCode).JSON(resp)
	}

	// 5. Handle Fiber/Generic errors
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		statusCode = fiberErr.Code
		resp.Message = fiberErr.Message
		resp.Kind = 0 // Or a specific transport error code
	} else {
		slog.Error("Unhandled Error", "path", c.Path(), "error", err.Error())
		resp.Message = err.Error()
	}

	return c.Status(statusCode).JSON(resp)
}
