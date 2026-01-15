package middlewares

import (
	"errors"
	"go_auth/internal/adapters/http" // Our Protocol Adapter
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"log/slog"
	netHTTP "net/http" // Alias to avoid collision with our adapter package

	"github.com/gofiber/fiber/v2"
)

func GlobalErrorHandler(c *fiber.Ctx, err error) error {
	if err == nil {
		return nil
	}

	// 1. Extract context metadata (Essential for consistent TraceID)
	ctxMeta := utils.GetContext(c)

	// 2. Initialize default response
	statusCode := netHTTP.StatusInternalServerError
	resp := dto.ErrorResponse{
		Success: false,
		Type:    string(apperr.TypeInternal),
		Message: "An unexpected system error occurred",
		TraceID: ctxMeta.RequestID, // Use the real TraceID from context by default
	}

	// 3. Handle Protocol Errors (The 400s we returned using http.NewBadRequest)
	if protoStatus := http.MapToStatus(err); protoStatus != 0 {
		statusCode = protoStatus
		resp.Type = "BAD_REQUEST"
		resp.Message = err.Error()

		slog.Warn("PROTOCOL_ERROR", "trace_id", resp.TraceID, "msg", err.Error())
		return c.Status(statusCode).JSON(resp)
	}

	// 4. Handle Structured Application Errors (Core Logic)
	var aErr *apperr.AppError
	if errors.As(err, &aErr) {
		resp.TraceID = aErr.TraceID
		resp.Type = string(aErr.Type)
		resp.Message = aErr.Message
		resp.Details = aErr.Details

		switch aErr.Type {
		case apperr.TypeValidation:
			statusCode = netHTTP.StatusUnprocessableEntity
		case apperr.TypeUnauthorized:
			statusCode = netHTTP.StatusUnauthorized
		case apperr.TypeForbidden:
			statusCode = netHTTP.StatusForbidden
		case apperr.TypeNotFound:
			statusCode = netHTTP.StatusNotFound
		case apperr.TypeConflict:
			statusCode = netHTTP.StatusConflict
		}

		// Log critical internal failures differently than client logic errors
		if aErr.Type == apperr.TypeInternal {
			slog.Error("INTERNAL_FAILURE", "trace_id", aErr.TraceID, "cause", aErr.Cause)
		}

		return c.Status(statusCode).JSON(resp)
	}

	// 5. Handle Fiber/Infrastructure Errors (e.g. 404 Route Not Found)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		statusCode = fiberErr.Code
		resp.Message = fiberErr.Message
		resp.Type = "INFRASTRUCTURE_ERROR"
	} else {
		slog.Error("UNHANDLED_EXCEPTION", "msg", err.Error(), "trace_id", resp.TraceID)
	}

	return c.Status(statusCode).JSON(resp)
}
