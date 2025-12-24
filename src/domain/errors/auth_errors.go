package errors

import "errors"

var (
	ErrInvalidCredentials          = errors.New("invalid credentials")
	ErrAccountDisabled             = errors.New("account disabled")
	ErrSessionExpired              = errors.New("session expired")
	ErrEmailAlreadyRegistered      = errors.New("email is already registered")
	ErrUserNotFound                = errors.New("user not found")
	ErrSessionNotFound             = errors.New("session not found")
	ErrUserNotMemberOfOrganization = errors.New("user is not a part of this organization")
	ErrInvalidToken                = errors.New("Invalid token")

	ErrDeviceRevoked     = errors.New("device is revoked")
	ErrDeviceInactive    = errors.New("device is inactive")
	ErrInvalidDeviceUser = errors.New("device does not belong to user")

	ErrRefreshTokenRevoked = errors.New("refresh token revoked")
	ErrRefreshTokenExpired = errors.New("refresh token expired")
	ErrInvalidTokenUser    = errors.New("refresh token does not belong to user")
)
