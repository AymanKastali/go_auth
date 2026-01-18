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

func NewGlobalErrorHandler(logger *slog.Logger) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		if err == nil {
			return nil
		}

		reqCtx := utils.ReqCtx(c)
		l := reqCtx.Logger.With(
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
		)

		statusCode := netHTTP.StatusInternalServerError
		resp := dto.ErrorResponse{
			Success: false,
			Type:    string(apperr.TypeInternal),
			Message: "An unexpected system error occurred",
			TraceID: reqCtx.RequestID,
		}

		if protoStatus := http.MapToStatus(err); protoStatus != 0 {
			statusCode = protoStatus
			resp.Type = "PROTOCOL_ERROR"
			resp.Message = err.Error()

			l.Warn("Protocol error detected", slog.String("error", err.Error()))
			return c.Status(statusCode).JSON(resp)
		}

		var aErr *apperr.AppError
		if errors.As(err, &aErr) {
			resp.Type = string(aErr.Type)
			resp.Message = aErr.Message
			resp.Details = aErr.Details

			switch aErr.Type {
			case apperr.TypeValidation:
				statusCode = netHTTP.StatusUnprocessableEntity
				l.Warn("Application validation failed", slog.Any("details", aErr.Details))
			case apperr.TypeUnauthorized:
				statusCode = netHTTP.StatusUnauthorized
				l.Warn("Unauthorized access attempt")
			case apperr.TypeNotFound:
				statusCode = netHTTP.StatusNotFound
				l.Debug("Resource not found", slog.String("message", aErr.Message))
			case apperr.TypeConflict:
				statusCode = netHTTP.StatusConflict
				l.Warn("Resource conflict", slog.String("message", aErr.Message))
			case apperr.TypeForbidden:
				statusCode = netHTTP.StatusForbidden
				l.Warn("Forbidden access attempt", slog.String("message", aErr.Message))
			case apperr.TypeInternal:
				l.Error("Application internal failure",
					slog.Any("error", aErr.Cause),
					slog.Any("details", aErr.Details),
				)
			default:
				l.Error("Unmapped application error type", slog.String("type", string(aErr.Type)))
			}

			return c.Status(statusCode).JSON(resp)
		}

		var fiberErr *fiber.Error
		if errors.As(err, &fiberErr) {
			statusCode = fiberErr.Code
			resp.Message = fiberErr.Message
			resp.Type = "INFRASTRUCTURE_ERROR"
			l.Warn("Fiber infrastructure error",
				slog.Int("status", fiberErr.Code),
				slog.String("error", fiberErr.Message),
			)
		} else {
			l.Error("Unhandled system exception", slog.Any("error", err))
		}

		return c.Status(statusCode).JSON(resp)
	}
}
