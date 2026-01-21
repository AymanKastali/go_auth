package entities

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type RenewalToken struct {
	id        valueobjects.TokenID
	userID    valueobjects.UserID
	deviceID  valueobjects.DeviceID
	hash      valueobjects.HashedToken
	expiresAt time.Time
	revokedAt *time.Time
	createdAt time.Time
}

func NewRenewalToken(
	id valueobjects.TokenID,
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	hash valueobjects.HashedToken,
	expiresAt time.Time,
	currentTime time.Time,
) (*RenewalToken, error) {
	if id.IsEmpty() {
		return nil, derr.ErrTokenIDRequired()
	}
	if userID.IsEmpty() {
		return nil, derr.ErrUserIDRequired()
	}
	if deviceID.IsEmpty() {
		return nil, derr.ErrDeviceIDRequired()
	}
	if expiresAt.IsZero() {
		return nil, derr.ErrExpiresAtRequired()
	}
	if currentTime.IsZero() {
		return nil, derr.ErrCurrentTimeRequired()
	}
	if hash.IsEmpty() {
		return nil, derr.ErrTokenHashRequired()
	}

	if expiresAt.Before(currentTime) {
		return nil, derr.ErrExpirationInPast()
	}

	return &RenewalToken{
		id:        id,
		userID:    userID,
		deviceID:  deviceID,
		hash:      hash,
		expiresAt: expiresAt,
		createdAt: currentTime,
	}, nil
}

func ReconstituteRenewalToken(
	id valueobjects.TokenID,
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	hash valueobjects.HashedToken,
	expiresAt time.Time,
	revokedAt *time.Time,
	createdAt time.Time,
) *RenewalToken {
	return &RenewalToken{
		id:        id,
		userID:    userID,
		deviceID:  deviceID,
		hash:      hash,
		expiresAt: expiresAt,
		revokedAt: revokedAt,
		createdAt: createdAt,
	}
}

func (e *RenewalToken) Revoke(currentTime time.Time) error {
	if e.IsRevoked() {
		return derr.ErrTokenRevoked(e.id.Value())
	}

	e.revokedAt = &currentTime
	return nil
}

func (e *RenewalToken) EnsureUsable(currentTime time.Time) error {
	tokenID := e.id.Value()
	if e.IsRevoked() {
		return derr.ErrTokenRevoked(tokenID)
	}
	if e.IsExpired(currentTime) {
		return derr.ErrTokenExpired(tokenID)
	}
	return nil
}

func (e *RenewalToken) BelongsTo(deviceID valueobjects.DeviceID) error {
	if !e.deviceID.Equal(deviceID) {
		return derr.ErrTokenDoesNotBelongToDevice(e.id.Value(), deviceID.Value())
	}
	return nil
}

func (e *RenewalToken) IsRevoked() bool                      { return e.revokedAt != nil }
func (e *RenewalToken) IsExpired(currentTime time.Time) bool { return currentTime.After(e.expiresAt) }

func (e *RenewalToken) IsActive(currentTime time.Time) bool {
	return !e.IsRevoked() && !e.IsExpired(currentTime)
}

func (e *RenewalToken) ID() valueobjects.TokenID        { return e.id }
func (e *RenewalToken) UserID() valueobjects.UserID     { return e.userID }
func (e *RenewalToken) DeviceID() valueobjects.DeviceID { return e.deviceID }
func (e *RenewalToken) Hash() valueobjects.HashedToken  { return e.hash }
func (e *RenewalToken) CreatedAt() time.Time            { return e.createdAt }
func (e *RenewalToken) ExpiresAt() time.Time            { return e.expiresAt }
func (e *RenewalToken) RevokedAt() *time.Time           { return e.revokedAt }
