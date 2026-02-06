package fiberapp

import (
	"errors"
	"go_auth/internal/core/application"
	"go_auth/internal/core/domain"
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"
)

// Error Handler
func NewErrorHandler() fiber.ErrorHandler {
	return func(c fiber.Ctx, e error) error {
		// Use the helper here as the primary source of truth
		traceID := requestid.FromContext(c)
		if traceID == "" {
			traceID = "unknown"
		}

		resp := ErrorResponse{
			TraceID: traceID,
			Code:    string(domain.KindInternal),
			Message: "Internal server error",
		}
		statusCode := fiber.StatusInternalServerError

		var appErr *domain.Error
		if errors.As(e, &appErr) {
			resp.Code = string(appErr.Kind())
			resp.Message = appErr.Message()
			statusCode = mapKindToHTTPStatus(appErr.Kind())

			logRequestError(c, statusCode, e)
			return c.Status(statusCode).JSON(resp)
		}

		var fErr *fiber.Error
		if errors.As(e, &fErr) {
			statusCode = fErr.Code
			resp.Code = "TRANSPORT_ERROR"
			resp.Message = fErr.Message
			logRequestError(c, statusCode, e)
			return c.Status(statusCode).JSON(resp)
		}

		logRequestError(c, statusCode, e)
		return c.Status(statusCode).JSON(resp)
	}
}

// Error Utils
func logRequestError(c fiber.Ctx, status int, e error) {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	// Default values for standard errors
	logLv := slog.LevelWarn
	appCode := "INTERNAL_ERROR"

	// Check if it's a domain error to extract more specific metadata
	var appErr *domain.Error
	if errors.As(e, &appErr) {
		appCode = string(appErr.Kind())
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

func mapKindToHTTPStatus(kind domain.Kind) int {
	switch kind {
	case domain.KindValidation:
		return fiber.StatusUnprocessableEntity
	case domain.KindUnauthorized:
		return fiber.StatusUnauthorized
	case domain.KindForbidden:
		return fiber.StatusForbidden
	case domain.KindNotFound:
		return fiber.StatusNotFound
	case domain.KindConflict:
		return fiber.StatusConflict
	case domain.KindBusinessRule:
		return fiber.StatusUnprocessableEntity
	default:
		return fiber.StatusInternalServerError
	}
}
