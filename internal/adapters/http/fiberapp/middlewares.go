package fiberapp

import (
	"context"
	"errors"
	"go_auth/internal/core/application"
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"
)

// Instead of manually calling MapToAppError
func AppErrorMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		err := c.Next()
		if err == nil {
			return nil
		}

		// --- Handle transport/adapters errors ---
		var fErr *fiber.Error
		if errors.As(err, &fErr) {
			return fErr
		}
		// --- Map domain/application errors ---
		return application.MapToAppError(err)
	}
}

func ContextMiddleware(baseLogger *slog.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Safe retrieval of request ID
		reqID := requestid.FromContext(c)

		// Scoped logger
		scopedLogger := baseLogger.With(
			slog.String("req_id", reqID),
		)

		// Build request context
		rc := NewRequestContext(
			reqID,
			c.Get("User-Agent"),
			c.IP(),
			c.Get("Accept-Language"),
			scopedLogger,
		)

		c.Locals("request_ctx", rc)

		c.Locals("request_ctx", rc)
		ctx := context.WithValue(c.Context(), requestCtxKey, rc)
		c.SetContext(ctx)

		return c.Next()
	}
}

// Protection Middleware
func Protected(validateUC application.IValidateAccessUseCase) fiber.Handler {
	return func(c fiber.Ctx) error {
		token := ExtractToken(c.Get("Authorization"))
		if token == "" {
			return application.MapToAppError(
				fiber.NewError(fiber.StatusUnauthorized, "missing authorization header"),
			)
		}

		query := application.ValidateAccessQuery{
			AccessToken: token,
			Fingerprint: c.Get("X-Fingerprint"),
		}

		access, err := validateUC.Execute(c.Context(), query)
		if err != nil {
			return err
		}

		// Fetch RequestContext from locals
		rcIface := c.Locals("request_ctx")
		if rcIface != nil {
			if rc, ok := rcIface.(*RequestContext); ok {
				rc.SetUser(access.UserID, access.SessionID, access.Roles)
			}
		}

		// Optionally also store in locals for quick access
		c.Locals("user_id", access.UserID)
		c.Locals("session_id", access.SessionID)

		return c.Next()
	}
}

// Error Handler
func NewErrorHandler() fiber.ErrorHandler {
	return func(c fiber.Ctx, err error) error {
		if err == nil {
			return nil
		}

		// Use the safe GetRequestContext function
		rc := GetRequestContext(c.Context())
		l := rc.Logger()

		if rc.IsAuthenticated() {
			l = l.With(
				slog.String("user_id", rc.UserID()),
				slog.String("session_id", rc.SessionID()),
				slog.Any("roles", rc.Roles()),
			)
		}

		statusCode := fiber.StatusInternalServerError
		resp := ErrorResponse{
			Code:    string(application.AppErrInternal),
			Message: "unexpected internal error",
			TraceID: rc.RequestID(),
		}

		// App Error Mapping
		var aErr *application.AppError
		if errors.As(err, &aErr) {
			resp.Code = string(aErr.Code)
			resp.Message = aErr.Message

			switch aErr.Code {
			case application.AppErrUnprocessable:
				statusCode = fiber.StatusUnprocessableEntity
				l.Warn("Validation failed", slog.String("error", aErr.Message))

			case application.AppErrUnauthorized:
				statusCode = fiber.StatusUnauthorized
				l.Warn("Unauthorized", slog.String("error", aErr.Message))

			case application.AppErrNotFound:
				statusCode = fiber.StatusNotFound
				l.Debug("Not found", slog.String("error", aErr.Message))

			case application.AppErrConflict:
				statusCode = fiber.StatusConflict
				l.Warn("Conflict", slog.String("error", aErr.Message))

			case application.AppErrForbidden:
				statusCode = fiber.StatusForbidden
				l.Warn("Forbidden", slog.String("error", aErr.Message))

			case application.AppErrInternal:
				statusCode = fiber.StatusInternalServerError
				l.Error("Internal error", slog.Any("cause", aErr.Err))
			}

			return c.Status(statusCode).JSON(resp)
		}

		// Fiber infrastructure errors
		var fiberErr *fiber.Error
		if errors.As(err, &fiberErr) {
			return c.Status(fiberErr.Code).JSON(ErrorResponse{
				Code:    "INFRA_ERROR",
				Message: fiberErr.Message,
				TraceID: rc.RequestID(),
			})
		}

		// Unknown panic / infrastructure error
		l.Error("Unhandled exception", slog.Any("err", err))

		return c.Status(statusCode).JSON(resp)
	}
}
