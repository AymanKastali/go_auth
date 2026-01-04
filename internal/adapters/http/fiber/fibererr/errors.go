package fibererr

import (
	"errors"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// Translate maps application errors (and Fiber errors) to HTTP responses
func TranslateErr(c *fiber.Ctx, err error) error {
	// ----------------------------
	// 1️⃣ Application Layer Errors
	// ----------------------------

	// Validation → 400
	var vErr *apperr.ValidationErr
	if errors.As(err, &vErr) {
		return utils.Failure(c, http.StatusBadRequest, vErr.Error(), "")
	}

	// Unauthorized → 401
	var uErr *apperr.UnauthorizedErr
	if errors.As(err, &uErr) {
		return utils.Failure(c, http.StatusUnauthorized, uErr.Error(), "")
	}

	// Not Found → 404
	var nErr *apperr.NotFoundErr
	if errors.As(err, &nErr) {
		return utils.Failure(c, http.StatusNotFound, nErr.Error(), "")
	}

	// Conflict → 409
	var cErr *apperr.ConflictErr
	if errors.As(err, &cErr) {
		return utils.Failure(c, http.StatusConflict, cErr.Error(), "")
	}

	// Already Exists → 409 (special conflict)
	var aErr *apperr.AlreadyExistsErr
	if errors.As(err, &aErr) {
		return utils.Failure(c, http.StatusConflict, aErr.Error(), "")
	}

	// Internal → 500
	var iErr *apperr.InternalErr
	if errors.As(err, &iErr) {
		return utils.Failure(c, http.StatusInternalServerError, iErr.Error(), "")
	}

	// ----------------------------
	// 2️⃣ Fiber Framework Errors
	// ----------------------------
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		return utils.Failure(c, fiberErr.Code, fiberErr.Message, "")
	}

	// ----------------------------
	// 3️⃣ Fallback for unknown errors
	// ----------------------------
	return utils.Failure(c, http.StatusInternalServerError, "internal server error", "")
}
