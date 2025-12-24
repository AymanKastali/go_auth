package entities

import (
	"go_auth/src/domain/errors"
	"go_auth/src/domain/value_objects"
	"time"
)

// TODO  add status
type RefreshToken struct {
	ID        value_objects.TokenId
	UserId    value_objects.UserId
	DeviceId  value_objects.DeviceId
	Token     string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

func (e *RefreshToken) Revoke(now time.Time) {
	e.RevokedAt = &now
}

// IsRevoked returns true if token is revoked
func (e *RefreshToken) IsRevoked() bool {
	return e.RevokedAt != nil
}

// IsExpired returns true if token is expired
func (e *RefreshToken) IsExpired(now time.Time) bool {
	return now.After(e.ExpiresAt)
}

// EnsureUsable checks both expiration and revocation
func (e *RefreshToken) EnsureUsable(now time.Time) error {
	if e.IsRevoked() {
		return errors.ErrRefreshTokenRevoked
	}
	if e.IsExpired(now) {
		return errors.ErrRefreshTokenExpired
	}
	return nil
}

// BelongsTo checks ownership
func (e *RefreshToken) BelongsTo(userId value_objects.UserId) error {
	if e.UserId != userId {
		return errors.ErrInvalidTokenUser
	}
	return nil
}
