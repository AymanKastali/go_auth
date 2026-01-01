package entities

import (
	"go_auth/internal/core/domain/domainerr"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

const (
	createRefreshTokenOp        = "RefreshToken.Create"
	reconstituteRefreshTokenOp  = "RefreshToken.Reconstitute"
	revokeTokenOp               = "RefreshToken.Revoke"
	ensureRefreshTokenUsableOp  = "RefreshToken.EnsureUsable"
	validateRefreshTokenOwnerOp = "RefreshToken.ValidateOwner"
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

	var missing []string

	if id.IsZero() {
		missing = append(missing, "id")
	}
	if userID.IsZero() {
		missing = append(missing, "user_id")
	}
	if deviceID.IsZero() {
		missing = append(missing, "device_id")
	}
	if token == "" {
		missing = append(missing, "token")
	}
	if expiresAt.IsZero() {
		missing = append(missing, "expires_at")
	}

	if len(missing) > 0 {
		return nil, domainerr.RequiredAttrsError(
			missing,
			createRefreshTokenOp,
		)
	}

	if !expiresAt.After(now) {
		return nil, domainerr.InvalidValueError(
			"expires_at",
			createRefreshTokenOp,
			nil,
		)
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
		return domainerr.OperationDeniedError(
			"deleted refresh token cannot be revoked",
			revokeTokenOp,
		)
	}

	if t.IsRevoked() {
		return domainerr.InvalidStateError(
			"refresh token is already revoked",
			revokeTokenOp,
		)
	}

	t.revokedAt = &now
	t.touch(now)
	return nil
}

func (t *RefreshToken) EnsureUsable(now time.Time) error {
	if t.deletedAt != nil {
		return domainerr.OperationDeniedError(
			"deleted refresh token cannot be used",
			ensureRefreshTokenUsableOp,
		)
	}

	if t.IsRevoked() {
		return domainerr.InvalidStateError(
			"refresh token is revoked",
			ensureRefreshTokenUsableOp,
		)
	}

	if t.IsExpired(now) {
		return domainerr.InvalidStateError(
			"refresh token is expired",
			ensureRefreshTokenUsableOp,
		)
	}

	return nil
}

func (t *RefreshToken) BelongsTo(userID valueobjects.UserID) error {
	if t.userID != userID {
		return domainerr.OperationDeniedError(
			"refresh token does not belong to user",
			validateRefreshTokenOwnerOp,
		)
	}

	return nil
}

func (t *RefreshToken) SoftDelete(now time.Time) error {
	if t.deletedAt != nil {
		return domainerr.InvalidStateError(
			"refresh token already deleted",
			revokeTokenOp,
		)
	}

	t.deletedAt = &now
	t.touch(now)
	return nil
}
