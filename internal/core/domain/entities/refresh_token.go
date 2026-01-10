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
	token     string
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
	token string,
	expiresAt time.Time,
	now time.Time,
) (*RefreshToken, error) {

	if id.IsEmpty() {
		return nil, derr.NewRequiredErr("token_id")
	}
	if userID.IsEmpty() {
		return nil, derr.NewRequiredErr("user_id")
	}
	if deviceID.IsEmpty() {
		return nil, derr.NewRequiredErr("device_id")
	}
	if token == "" {
		return nil, derr.NewRequiredErr("token")
	}
	if expiresAt.IsZero() {
		return nil, derr.NewRequiredErr("expires_at")
	}

	// Business Rule: Cannot issue an already expired token
	if expiresAt.Before(now) {
		return nil, derr.NewInvalidValueErr("expires_at", "expiration date must not be in the past")
	}

	return &RefreshToken{
		id:        id,
		userID:    userID,
		deviceID:  deviceID,
		token:     token,
		expiresAt: expiresAt,
		createdAt: now,
		updatedAt: now,
	}, nil
}

func ReconstituteRefreshToken(
	id valueobjects.TokenID,
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	token string,
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

func (t *RefreshToken) ID() valueobjects.TokenID {
	return t.id
}
func (t *RefreshToken) UserID() valueobjects.UserID {
	return t.userID
}
func (t *RefreshToken) DeviceID() valueobjects.DeviceID {
	return t.deviceID
}
func (t *RefreshToken) Token() string {
	return t.token
}
func (t *RefreshToken) CreatedAt() time.Time {
	return t.createdAt
}
func (t *RefreshToken) UpdatedAt() time.Time {
	return t.updatedAt
}
func (t *RefreshToken) ExpiresAt() time.Time {
	return t.expiresAt
}
func (t *RefreshToken) RevokedAt() *time.Time {
	return t.revokedAt
}
func (t *RefreshToken) IsRevoked() bool {
	return t.revokedAt != nil
}
func (t *RefreshToken) IsExpired(now time.Time) bool {
	return now.After(t.expiresAt)
}

func (t *RefreshToken) touch(now time.Time) {
	t.updatedAt = now
}
func (t *RefreshToken) Revoke(now time.Time) error {
	if t.deletedAt != nil {
		return derr.NewRuleViolationErr("cannot revoke a deleted token")
	}

	if t.IsRevoked() {
		return derr.NewRuleViolationErr("refresh token is already revoked")
	}

	t.revokedAt = &now
	t.touch(now)
	return nil
}

func (t *RefreshToken) EnsureUsable(now time.Time) error {
	if t.deletedAt != nil {
		return derr.NewRuleViolationErr("token has been deleted")
	}

	if t.IsRevoked() {
		return derr.NewRuleViolationErr("token has been revoked")
	}

	if t.IsExpired(now) {
		return derr.NewRuleViolationErr("token has expired")
	}

	return nil
}

func (t *RefreshToken) BelongsTo(userID valueobjects.UserID) error {
	if !t.userID.Equal(userID) {
		return derr.NewInvalidValueErr("user_id", "token ownership mismatch")
	}

	return nil
}

func (t *RefreshToken) SoftDelete(now time.Time) error {
	if t.deletedAt != nil {
		return derr.NewRuleViolationErr("token already deleted")
	}

	t.deletedAt = &now
	t.touch(now)
	return nil
}
