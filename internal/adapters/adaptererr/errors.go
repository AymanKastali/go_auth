package adaptererr

import (
	"errors"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/domainerr"
	"net/http"
)

// ErrorResponse is the standard JSON contract for your API consumers
type ErrorResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"` // For validation errors
}

func Translate(err error) (int, ErrorResponse) {
	// 1. Check for Domain-level errors (Validation/Rules)
	// We use errors.As because we want to extract the Attr() field
	var dErr domainerr.DomainError
	if errors.As(err, &dErr) {
		return http.StatusBadRequest, ErrorResponse{
			Success: false,
			Message: dErr.Error(),
			Field:   dErr.Attr(),
		}
	}

	// 2. Check for Application-level errors (Business Logic Outcomes)
	// We use errors.Is for sentinel errors
	if errors.Is(err, apperr.ErrInvalidCredentials) {
		return http.StatusUnauthorized, ErrorResponse{
			Success: false,
			Message: "Authentication failed. Check your email and password.",
		}
	}

	if errors.Is(err, apperr.ErrNotFound) {
		return http.StatusNotFound, ErrorResponse{
			Success: false,
			Message: "The requested resource could not be found.",
		}
	}

	// 3. The Catch-All (Internal Server Error)
	// This covers apperr.ErrInternal and any unhandled errors
	return http.StatusInternalServerError, ErrorResponse{
		Success: false,
		Message: "An unexpected error occurred. Please try again later.",
	}
}
