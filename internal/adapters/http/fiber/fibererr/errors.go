package fibererr

import (
	"errors"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// Translate now calls utils.Failure directly to ensure unified output
func Translate(c *fiber.Ctx, err error) error {
	// 1. Handle Application Layer Errors
	var aErr *apperr.AppError
	if errors.As(err, &aErr) {
		status := http.StatusInternalServerError

		switch aErr.Code() {
		case apperr.CodeInvalidInput:
			status = http.StatusBadRequest
		case apperr.CodeUnauthorized:
			status = http.StatusUnauthorized
		case apperr.CodeNotFound:
			status = http.StatusNotFound
		case apperr.CodeConflict:
			status = http.StatusConflict
		case apperr.CodeUnprocessable:
			status = http.StatusUnprocessableEntity
		}

		return utils.Failure(c, status, aErr.Error(), aErr.Field())
	}

	// 2. Handle Adapter/Framework Errors (Fiber Errors)
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		return utils.Failure(c, fiberErr.Code, fiberErr.Message, "")
	}

	// 3. Fallback for unknown errors
	return utils.Failure(c, http.StatusInternalServerError, "Internal Error", "")
}
