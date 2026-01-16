package middlewares

import (
	"errors"
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"log/slog"
	netHTTP "net/http"

	"github.com/gofiber/fiber/v2"
)

// NewGlobalErrorHandler returns a fiber.ErrorHandler that uses a structured logger.
func NewGlobalErrorHandler(logger *slog.Logger) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		if err == nil {
			return nil
		}

		ctxMeta := utils.GetContext(c)

		// Create a logger enriched with request context
		l := logger.With(
			slog.String("trace_id", ctxMeta.RequestID),
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
			slog.String("ip", c.IP()),
		)

		statusCode := netHTTP.StatusInternalServerError
		resp := dto.ErrorResponse{
			Success: false,
			Type:    string(apperr.TypeInternal),
			Message: "An unexpected system error occurred",
			TraceID: ctxMeta.RequestID,
		}

		// 1. Handle Protocol Errors (400s)
		if protoStatus := http.MapToStatus(err); protoStatus != 0 {
			statusCode = protoStatus
			resp.Type = "BAD_REQUEST"
			resp.Message = err.Error()

			l.Warn("protocol_error", slog.String("msg", err.Error()))
			return c.Status(statusCode).JSON(resp)
		}

		// 2. Handle Structured Application Errors
		var aErr *apperr.AppError
		if errors.As(err, &aErr) {
			resp.Type = string(aErr.Type)
			resp.Message = aErr.Message
			resp.Details = aErr.Details

			switch aErr.Type {
			case apperr.TypeValidation:
				statusCode = netHTTP.StatusUnprocessableEntity
				l.Warn("validation_failed", slog.Any("details", aErr.Details))
			case apperr.TypeUnauthorized:
				statusCode = netHTTP.StatusUnauthorized
				l.Warn("unauthorized_access")
			case apperr.TypeNotFound:
				statusCode = netHTTP.StatusNotFound
				l.Debug("resource_not_found", slog.String("msg", aErr.Message))
			case apperr.TypeConflict:
				statusCode = netHTTP.StatusConflict
				l.Warn("resource_conflict", slog.String("msg", aErr.Message))
			case apperr.TypeInternal:
				l.Error("application_internal_failure",
					slog.String("cause", aErr.Cause.Error()),
					slog.Any("details", aErr.Details),
				)
			default:
				l.Error("unmapped_app_error", slog.String("type", string(aErr.Type)))
			}

			return c.Status(statusCode).JSON(resp)
		}

		// 3. Handle Fiber/Infrastructure Errors (e.g., 404 Route Not Found)
		var fiberErr *fiber.Error
		if errors.As(err, &fiberErr) {
			statusCode = fiberErr.Code
			resp.Message = fiberErr.Message
			resp.Type = "INFRASTRUCTURE_ERROR"
			l.Warn("fiber_infrastructure_error", slog.Int("status", fiberErr.Code), slog.String("msg", fiberErr.Message))
		} else {
			// 4. Catch-all for everything else
			l.Error("unhandled_exception", slog.String("error", err.Error()))
		}

		return c.Status(statusCode).JSON(resp)
	}
}
