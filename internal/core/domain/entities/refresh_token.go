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
	now time.Time,
) (*RefreshToken, error) {

	if id.IsEmpty() {
		return nil, derr.NewRequiredErr("tokenID")
	}
	if userID.IsEmpty() {
		return nil, derr.NewRequiredErr("userID")
	}
	if deviceID.IsEmpty() {
		return nil, derr.NewRequiredErr("deviceID")
	}
	if token.IsEmpty() {
		return nil, derr.NewRequiredErr("token")
	}
	if expiresAt.IsZero() {
		return nil, derr.NewRequiredErr("expiresAt")
	}

	if expiresAt.Before(now) {
		return nil, derr.NewInvalidValueErr("expiresAt")
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

func (e *RefreshToken) ID() valueobjects.TokenID {
	return e.id
}
func (e *RefreshToken) UserID() valueobjects.UserID {
	return e.userID
}
func (e *RefreshToken) DeviceID() valueobjects.DeviceID {
	return e.deviceID
}
func (e *RefreshToken) Token() valueobjects.Token {
	return e.token
}
func (e *RefreshToken) CreatedAt() time.Time {
	return e.createdAt
}
func (e *RefreshToken) UpdatedAt() time.Time {
	return e.updatedAt
}
func (e *RefreshToken) ExpiresAt() time.Time {
	return e.expiresAt
}
func (e *RefreshToken) RevokedAt() *time.Time {
	return e.revokedAt
}
func (e *RefreshToken) IsRevoked() bool {
	return e.revokedAt != nil
}
func (e *RefreshToken) IsExpired(now time.Time) bool {
	return now.After(e.expiresAt)
}

func (e *RefreshToken) Revoke(now time.Time) error {
	if e.deletedAt != nil {
		return derr.NewRuleViolationErr("cannot revoke a deleted token")
	}

	if e.IsRevoked() {
		return derr.NewRuleViolationErr("refresh token is already revoked")
	}

	e.revokedAt = &now
	e.touch(now)
	return nil
}

func (e *RefreshToken) EnsureUsable(now time.Time) error {
	if e.deletedAt != nil {
		return derr.NewRuleViolationErr("token has been deleted")
	}

	if e.IsRevoked() {
		return derr.NewRuleViolationErr("token has been revoked")
	}

	if e.IsExpired(now) {
		return derr.NewRuleViolationErr("token has expired")
	}

	return nil
}

func (e *RefreshToken) BelongsTo(userID valueobjects.UserID) error {
	if !e.userID.Equal(userID) {
		return derr.NewInvalidValueErr("UserID")
	}

	return nil
}

func (e *RefreshToken) SoftDelete(now time.Time) error {
	if e.deletedAt != nil {
		return derr.NewRuleViolationErr("token already deleted")
	}

	e.deletedAt = &now
	e.touch(now)
	return nil
}

func (e *RefreshToken) IsDeleted() bool {
	return e.deletedAt != nil
}

func (e *RefreshToken) IsActive(now time.Time) bool {
	return !e.IsDeleted() &&
		!e.IsRevoked() &&
		!e.IsExpired(now)
}

func (e *RefreshToken) touch(now time.Time) {
	e.updatedAt = now
}
