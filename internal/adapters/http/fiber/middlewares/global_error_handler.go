package middlewares

import (
	"errors"
	"go_auth/internal/adapters/shared/errors/cfgerr"
	"go_auth/internal/core/application/apperr"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

func GlobalErrorHandler(c *fiber.Ctx, err error) error {
	// 1️⃣ Default: Internal Server Error (500)
	code := http.StatusInternalServerError
	errType := "Internal Server Error"
	message := "An unexpected error occurred"

	// 2️⃣ Check for Custom Application Errors
	var (
		configErr cfgerr.ConfigErr

		badRequest   *apperr.BadRequestErr
		notFound     *apperr.NotFoundErr
		conflict     *apperr.ConflictErr
		exists       *apperr.AlreadyExistsErr
		validation   *apperr.ValidationErr
		unauthorized *apperr.UnauthorizedErr
		forbidden    *apperr.ForbiddenErr
		internal     *apperr.InternalErr
	)

	switch {
	case errors.As(err, &configErr):
		code = http.StatusInternalServerError
		errType = "Configuration Error"
		message = "The server is improperly configured."

	case errors.As(err, &validation):
		code = http.StatusBadRequest
		errType = "Validation Error"
		message = validation.Error()

	case errors.As(err, &unauthorized):
		code = http.StatusUnauthorized
		errType = "Unauthorized"
		message = unauthorized.Error()

	case errors.As(err, &forbidden):
		code = http.StatusForbidden
		errType = "Forbidden"
		message = forbidden.Error()

	case errors.As(err, &badRequest):
		code = http.StatusBadRequest
		errType = "Bad Request"
		message = badRequest.Error()

	case errors.As(err, &notFound):
		code = http.StatusNotFound
		errType = "Not Found"
		message = notFound.Error()

	case errors.As(err, &conflict):
		code = http.StatusConflict
		errType = "Conflict"
		message = conflict.Error()

	case errors.As(err, &exists):
		code = http.StatusConflict
		errType = "Already Exists"
		message = exists.Error()

	case errors.As(err, &internal):
		code = http.StatusInternalServerError
		errType = "Internal Error"
		message = internal.Error()
	}

	return c.Status(code).JSON(fiber.Map{
		"success": false,
		"error":   errType,
		"message": message,
		"code":    code,
	})
}
