package derr

import "fmt"

type ErrDeviceDoesNotBelongToUser struct {
	UserID   string
	DeviceID string
}

func NewErrDeviceDoesNotBelongToUser(userID, deviceID string) *ErrDeviceDoesNotBelongToUser {
	return &ErrDeviceDoesNotBelongToUser{UserID: userID, DeviceID: deviceID}
}

func (e *ErrDeviceDoesNotBelongToUser) Error() string {
	return fmt.Sprintf("security violation: device '%s' does not belong to user '%s'", e.DeviceID, e.UserID)
}

func (e *ErrDeviceDoesNotBelongToUser) Code() ErrorCode { return CodeForbidden }

type ErrSessionCompromised struct{ UserID string }

func NewErrSessionCompromised(userID string) *ErrSessionCompromised {
	return &ErrSessionCompromised{UserID: userID}
}

func (e *ErrSessionCompromised) Error() string {
	return fmt.Sprintf("security alert: session for user %s has been compromised (token reuse detected)", e.UserID)
}
func (e *ErrSessionCompromised) Code() ErrorCode { return CodeForbidden }

type ErrDeviceRevoked struct{ DeviceID string }

func NewErrDeviceRevoked(deviceID string) *ErrDeviceRevoked {
	return &ErrDeviceRevoked{DeviceID: deviceID}
}
func (e *ErrDeviceRevoked) Error() string {
	return fmt.Sprintf("device '%s' has been revoked", e.DeviceID)
}
func (e *ErrDeviceRevoked) Code() ErrorCode { return CodeForbidden }

type ErrSessionRenewalTokenRevoked struct{ SessionRenewalRawTokenID string }

func NewErrSessionRenewalTokenRevoked(tokenID string) *ErrSessionRenewalTokenRevoked {
	return &ErrSessionRenewalTokenRevoked{SessionRenewalRawTokenID: tokenID}
}
func (e *ErrSessionRenewalTokenRevoked) Error() string {
	return fmt.Sprintf("session renewal token '%s' has been revoked", e.SessionRenewalRawTokenID)
}
func (e *ErrSessionRenewalTokenRevoked) Code() ErrorCode { return CodeForbidden }

type ErrSessionRenewalTokenExpired struct {
	SessionRenewalRawTokenID string
}

func NewErrSessionRenewalTokenExpired(tokenID string) *ErrSessionRenewalTokenExpired {
	return &ErrSessionRenewalTokenExpired{SessionRenewalRawTokenID: tokenID}
}
func (e *ErrSessionRenewalTokenExpired) Error() string {
	return fmt.Sprintf("session renewal token '%s' has expired", e.SessionRenewalRawTokenID)
}
func (e *ErrSessionRenewalTokenExpired) Code() ErrorCode { return CodeForbidden }
