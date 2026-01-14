package entities

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type RefreshToken struct {
	id        valueobjects.TokenID
	userID    valueobjects.UserID
	deviceID  valueobjects.DeviceID
	token     valueobjects.Token
	expiresAt time.Time
	revokedAt *time.Time
	createdAt time.Time
	updatedAt time.Time
	deletedAt *time.Time
}

func NewRefreshToken(
	id valueobjects.TokenID,
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	token valueobjects.Token,
	expiresAt time.Time,
	currentTime time.Time,
) (*RefreshToken, error) {
	if id.IsEmpty() {
		return nil, derr.ErrTokenIDRequired()
	}
	if userID.IsEmpty() {
		return nil, derr.ErrUserIDRequired()
	}
	if deviceID.IsEmpty() {
		return nil, derr.ErrDeviceIDRequired()
	}
	if token.IsEmpty() {
		return nil, derr.ErrTokenRequired()
	}
	if expiresAt.IsZero() {
		return nil, derr.ErrExpiresAtRequired()
	}
	if currentTime.IsZero() {
		return nil, derr.ErrCurrentTimeRequired()
	}

	if expiresAt.Before(currentTime) {
		return nil, derr.ErrExpirationInPast()
	}

	return &RefreshToken{
		id:        id,
		userID:    userID,
		deviceID:  deviceID,
		token:     token,
		expiresAt: expiresAt,
		createdAt: currentTime,
		updatedAt: currentTime,
	}, nil
}

func ReconstituteRefreshToken(
	id valueobjects.TokenID,
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	token valueobjects.Token,
	expiresAt time.Time,
	revokedAt *time.Time,
	createdAt time.Time,
	updatedAt time.Time,
	deletedAt *time.Time,
) *RefreshToken {
	return &RefreshToken{
		id:        id,
		userID:    userID,
		deviceID:  deviceID,
		token:     token,
		expiresAt: expiresAt,
		revokedAt: revokedAt,
		createdAt: createdAt,
		updatedAt: updatedAt,
		deletedAt: deletedAt,
	}
}

// --- Domain Actions ---

func (e *RefreshToken) Revoke(currentTime time.Time) error {
	if e.IsDeleted() {
		// Use specific violation for deleted state
		return derr.ErrTokenDeleted(e.id.Value())
	}
	if e.IsRevoked() {
		return derr.ErrTokenRevoked(e.id.Value())
	}

	e.revokedAt = &currentTime
	e.touch(currentTime)
	return nil
}

func (e *RefreshToken) SoftDelete(currentTime time.Time) error {
	if e.IsDeleted() {
		return derr.ErrTokenDeleted(e.id.Value())
	}

	e.deletedAt = &currentTime
	e.touch(currentTime)
	return nil
}

// --- Invariants & Helpers ---

func (e *RefreshToken) EnsureUsable(currentTime time.Time) error {
	tokenID := e.id.Value()
	if e.IsDeleted() {
		return derr.ErrTokenDeleted(tokenID)
	}
	if e.IsRevoked() {
		return derr.ErrTokenRevoked(tokenID)
	}
	if e.IsExpired(currentTime) {
		return derr.ErrTokenExpired(tokenID)
	}
	return nil
}

func (e *RefreshToken) BelongsTo(deviceID valueobjects.DeviceID) error {
	if !e.deviceID.Equal(deviceID) {
		return derr.ErrTokenDoesNotBelongToDevice(e.id.Value(), deviceID.Value())
	}
	return nil
}

func (e *RefreshToken) IsRevoked() bool                      { return e.revokedAt != nil }
func (e *RefreshToken) IsDeleted() bool                      { return e.deletedAt != nil }
func (e *RefreshToken) IsExpired(currentTime time.Time) bool { return currentTime.After(e.expiresAt) }

func (e *RefreshToken) IsActive(currentTime time.Time) bool {
	return !e.IsDeleted() && !e.IsRevoked() && !e.IsExpired(currentTime)
}

func (e *RefreshToken) touch(currentTime time.Time) {
	e.updatedAt = currentTime
}

// --- Getters ---

func (e *RefreshToken) ID() valueobjects.TokenID        { return e.id }
func (e *RefreshToken) UserID() valueobjects.UserID     { return e.userID }
func (e *RefreshToken) DeviceID() valueobjects.DeviceID { return e.deviceID }
func (e *RefreshToken) Token() valueobjects.Token       { return e.token }
func (e *RefreshToken) CreatedAt() time.Time            { return e.createdAt }
func (e *RefreshToken) UpdatedAt() time.Time            { return e.updatedAt }
func (e *RefreshToken) ExpiresAt() time.Time            { return e.expiresAt }
func (e *RefreshToken) RevokedAt() *time.Time           { return e.revokedAt }
func (e *RefreshToken) DeletedAt() *time.Time           { return e.deletedAt }
