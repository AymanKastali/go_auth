package aggregates

import (
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

// This promotes Dependency Inversion (DIP) and makes the aggregate testable.
type AuthSessionIDFactory interface {
	NewTokenID() valueobjects.TokenID
}
type AuthSession struct {
	tokenID      valueobjects.TokenID
	userID       valueobjects.UserID
	accessToken  valueobjects.JWTToken
	refreshToken valueobjects.JWTToken
	expiresAt    valueobjects.TokenExpiry
	device       valueobjects.DeviceFingerprint
	createdAt    time.Time
}

func NewAuthSession(
	factory AuthSessionIDFactory, // <-- Dependency Injection (DI)
	userID valueobjects.UserID,
	access valueobjects.JWTToken,
	refresh valueobjects.JWTToken,
	expiry valueobjects.TokenExpiry,
	device valueobjects.DeviceFingerprint,
) *AuthSession {
	return &AuthSession{
		tokenID:      factory.NewTokenID(),
		userID:       userID,
		accessToken:  access,
		refreshToken: refresh,
		expiresAt:    expiry,
		device:       device,
		createdAt:    time.Now(),
	}
}

func (a *AuthSession) TokenID() valueobjects.TokenID {
	return a.tokenID
}

func (a *AuthSession) UserID() valueobjects.UserID {
	return a.userID
}

func (a *AuthSession) AccessToken() valueobjects.JWTToken {
	return a.accessToken
}

func (a *AuthSession) RefreshToken() valueobjects.JWTToken {
	return a.refreshToken
}

func (a *AuthSession) IsExpired() bool {
	return a.expiresAt.IsExpired()
}
