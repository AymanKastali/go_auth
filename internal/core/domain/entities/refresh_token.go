package entities

import (
	"go_auth/internal/core/domain/domainerr"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

// TODO  add status
type RefreshToken struct {
	ID        valueobjects.TokenID
	UserID    valueobjects.UserID
	DeviceID  valueobjects.DeviceID
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
		return domainerr.ErrRefreshTokenRevoked
	}
	if e.IsExpired(now) {
		return domainerr.ErrRefreshTokenExpired
	}
	return nil
}

// BelongsTo checks ownership
func (e *RefreshToken) BelongsTo(userID valueobjects.UserID) error {
	if e.UserID != userID {
		return domainerr.ErrInvalidTokenUser
	}
	return nil
}
