package entities

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
)

type RefreshToken struct {
	id          valueobjects.TokenID
	userID      valueobjects.UserID
	deviceID    valueobjects.DeviceID
	hashedToken valueobjects.HashedToken
	expiresAt   valueobjects.Timepoint
	revokedAt   *valueobjects.Timepoint
	createdAt   valueobjects.Timepoint
}

func NewRefreshToken(
	id valueobjects.TokenID,
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	hash valueobjects.HashedToken,
	expiresAt valueobjects.Timepoint,
	now valueobjects.Timepoint,
) (*RefreshToken, error) {
	if id.IsEmpty() {
		return nil, derr.NewErrRefreshTokenIDRequired()
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

	return &RefreshToken{
		id:          id,
		userID:      userID,
		deviceID:    deviceID,
		hashedToken: hash,
		expiresAt:   expiresAt,
		createdAt:   now,
	}, nil
}

func ReconstituteRefreshToken(
	id valueobjects.TokenID,
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	hashedToken valueobjects.HashedToken,
	createdAt valueobjects.Timepoint,
	expiresAt valueobjects.Timepoint,
	revokedAt *valueobjects.Timepoint,
) *RefreshToken {
	return &RefreshToken{
		id:          id,
		userID:      userID,
		deviceID:    deviceID,
		hashedToken: hashedToken,
		expiresAt:   expiresAt,
		revokedAt:   revokedAt,
		createdAt:   createdAt,
	}
}

func (e *RefreshToken) Revoke(now valueobjects.Timepoint) error {
	if e.IsRevoked() {
		return derr.NewErrRefreshTokenRevoked(e.id.String())
	}

	e.revokedAt = &now
	return nil
}

func (e *RefreshToken) EnsureUsable(now valueobjects.Timepoint) error {
	tokenID := e.id.String()
	if e.IsRevoked() {
		return derr.NewErrRefreshTokenRevoked(tokenID)
	}
	if e.IsExpired(now) {
		return derr.NewErrRefreshTokenExpired(tokenID)
	}
	return nil
}

func (e *RefreshToken) BelongsTo(deviceID valueobjects.DeviceID) error {
	if !e.deviceID.Equal(deviceID) {
		return derr.NewErrTokenDoesNotBelongToDevice(e.id.String(), deviceID.String())
	}
	return nil
}

func (e *RefreshToken) IsRevoked() bool { return e.revokedAt != nil }
func (e *RefreshToken) IsExpired(now valueobjects.Timepoint) bool {
	return now.IsAfter(e.expiresAt)
}

func (e *RefreshToken) IsActive(now valueobjects.Timepoint) bool {
	return !e.IsRevoked() && !e.IsExpired(now)
}

func (e *RefreshToken) ID() valueobjects.TokenID              { return e.id }
func (e *RefreshToken) UserID() valueobjects.UserID           { return e.userID }
func (e *RefreshToken) DeviceID() valueobjects.DeviceID       { return e.deviceID }
func (e *RefreshToken) HashedToken() valueobjects.HashedToken { return e.hashedToken }
func (e *RefreshToken) CreatedAt() valueobjects.Timepoint     { return e.createdAt }
func (e *RefreshToken) ExpiresAt() valueobjects.Timepoint     { return e.expiresAt }
func (e *RefreshToken) RevokedAt() *valueobjects.Timepoint    { return e.revokedAt }
