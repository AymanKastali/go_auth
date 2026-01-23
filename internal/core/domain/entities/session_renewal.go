package entities

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
)

type SessionRenewalToken struct {
	id          valueobjects.SessionRenewalTokenID
	userID      valueobjects.UserID
	deviceID    valueobjects.DeviceID
	hashedToken valueobjects.SessionRenewalHashedToken
	expiresAt   valueobjects.Timepoint
	revokedAt   *valueobjects.Timepoint
	createdAt   valueobjects.Timepoint
}

func NewSessionRenewalToken(
	id valueobjects.SessionRenewalTokenID,
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	hash valueobjects.SessionRenewalHashedToken,
	expiresAt valueobjects.Timepoint,
	now valueobjects.Timepoint,
) (*SessionRenewalToken, error) {
	if id.IsEmpty() {
		return nil, derr.NewErrSessionRenewalTokenIDRequired()
	}
	if userID.IsEmpty() {
		return nil, derr.NewErrUserIDRequired()
	}
	if deviceID.IsEmpty() {
		return nil, derr.NewErrDeviceIDRequired()
	}
	if hash.IsEmpty() {
		return nil, derr.NewErrTokenHashRequired()
	}
	if expiresAt.IsZero() {
		return nil, derr.NewErrExpirationRequired()
	}
	if now.IsZero() {
		return nil, derr.NewErrTimepointRequired()
	}
	if expiresAt.IsBefore(now) {
		return nil, derr.NewErrExpirationInPast()
	}

	return &SessionRenewalToken{
		id:          id,
		userID:      userID,
		deviceID:    deviceID,
		hashedToken: hash,
		expiresAt:   expiresAt,
		createdAt:   now,
	}, nil
}

func ReconstituteSessionRenewalToken(
	id valueobjects.SessionRenewalTokenID,
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	hashedToken valueobjects.SessionRenewalHashedToken,
	createdAt valueobjects.Timepoint,
	expiresAt valueobjects.Timepoint,
	revokedAt *valueobjects.Timepoint,
) *SessionRenewalToken {
	return &SessionRenewalToken{
		id:          id,
		userID:      userID,
		deviceID:    deviceID,
		hashedToken: hashedToken,
		expiresAt:   expiresAt,
		revokedAt:   revokedAt,
		createdAt:   createdAt,
	}
}

func (e *SessionRenewalToken) Revoke(now valueobjects.Timepoint) error {
	if e.IsRevoked() {
		return derr.NewErrSessionRenewalTokenRevoked(e.id.String())
	}

	e.revokedAt = &now
	return nil
}

func (e *SessionRenewalToken) EnsureUsable(now valueobjects.Timepoint) error {
	tokenID := e.id.String()
	if e.IsRevoked() {
		return derr.NewErrSessionRenewalTokenRevoked(tokenID)
	}
	if e.IsExpired(now) {
		return derr.NewErrSessionRenewalTokenExpired(tokenID)
	}
	return nil
}

func (e *SessionRenewalToken) BelongsTo(deviceID valueobjects.DeviceID) error {
	if !e.deviceID.Equal(deviceID) {
		return derr.NewErrTokenDoesNotBelongToDevice(e.id.String(), deviceID.String())
	}
	return nil
}

func (e *SessionRenewalToken) IsRevoked() bool { return e.revokedAt != nil }
func (e *SessionRenewalToken) IsExpired(now valueobjects.Timepoint) bool {
	return now.IsAfter(e.expiresAt)
}

func (e *SessionRenewalToken) IsActive(now valueobjects.Timepoint) bool {
	return !e.IsRevoked() && !e.IsExpired(now)
}

func (e *SessionRenewalToken) ID() valueobjects.SessionRenewalTokenID { return e.id }
func (e *SessionRenewalToken) UserID() valueobjects.UserID            { return e.userID }
func (e *SessionRenewalToken) DeviceID() valueobjects.DeviceID        { return e.deviceID }
func (e *SessionRenewalToken) SessionRenewalHashedToken() valueobjects.SessionRenewalHashedToken {
	return e.hashedToken
}
func (e *SessionRenewalToken) CreatedAt() valueobjects.Timepoint  { return e.createdAt }
func (e *SessionRenewalToken) ExpiresAt() valueobjects.Timepoint  { return e.expiresAt }
func (e *SessionRenewalToken) RevokedAt() *valueobjects.Timepoint { return e.revokedAt }
