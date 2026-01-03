package adaptererr

import (
	"errors"
	"net/http"

	"go_auth/internal/core/application/apperr"
)

func FromApplication(err error) (status int, message string) {
	var appErr *apperr.AppError
	if !errors.As(err, &appErr) {
		return http.StatusInternalServerError, "internal server error"
	}

	switch appErr.Code() {
	case apperr.CodeInvalidValue:
		return http.StatusBadRequest, appErr.Error()

	case apperr.CodeInvalidCredentials:
		return http.StatusUnauthorized, "invalid credentials"

	case apperr.CodeUserInactive:
		return http.StatusForbidden, "user is inactive"

	case apperr.CodeDeviceNotUsable:
		return http.StatusUnauthorized, "device is not usable"

	case apperr.CodeDeviceNotFound:
		return http.StatusUnauthorized, "device not found"

	case apperr.CodeEmailExists:
		return http.StatusConflict, "email already registered"

	default:
		return http.StatusInternalServerError, "internal server error"
	}
}
