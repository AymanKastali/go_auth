package adapters

import (
	"errors"
	"go_auth/internal/core/application"

	"github.com/gofiber/fiber/v3"
)

var (
	ErrIDMapping       = errors.New("failed to map generated string to domain ID")
	ErrTokenMapping    = errors.New("failed to map generated string to domain token")
	ErrTokenGeneration = errors.New("failed to generate secure random bytes")
	ErrTokenSignature  = errors.New("token signature mismatch")
	ErrClaimsInvalid   = errors.New("token contains invalid or missing claims")
)

func MapAppErrorToHTTP(appErr *application.AppError) int {
	switch appErr.Code {
	case application.AppErrUnauthorized:
		return fiber.StatusUnauthorized
	case application.AppErrForbidden:
		return fiber.StatusForbidden
	case application.AppErrNotFound:
		return fiber.StatusNotFound
	case application.AppErrConflict:
		return fiber.StatusConflict
	case application.AppErrUnprocessable:
		return fiber.StatusUnprocessableEntity
	default:
		return fiber.StatusInternalServerError
	}
}

// Transport-only errors (Explicitly not in Application layer)
func ErrBadRequest(message string) error {
	return fiber.NewError(fiber.StatusBadRequest, message)
}

func ErrTooManyRequests(message string) error {
	return fiber.NewError(fiber.StatusTooManyRequests, message)
}

func ErrInternal(message string) error {
	return fiber.NewError(fiber.StatusInternalServerError, message)
}
