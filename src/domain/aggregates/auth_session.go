package aggregates

import (
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

type AuthSession struct {
	tokenID      valueobjects.TokenID
	userID       valueobjects.UserID
	accessToken  valueobjects.AccessToken
	refreshToken valueobjects.RefreshToken
	expiresAt    valueobjects.TokenExpiry
	device       valueobjects.DeviceFingerprint
	createdAt    time.Time
}

func NewAuthSession(
	userID valueobjects.UserID,
	access valueobjects.AccessToken,
	refresh valueobjects.RefreshToken,
	expiry valueobjects.TokenExpiry,
	device valueobjects.DeviceFingerprint,
) *AuthSession {
	return &AuthSession{
		tokenID:      valueobjects.NewTokenID(),
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

func (a *AuthSession) AccessToken() valueobjects.AccessToken {
	return a.accessToken
}

func (a *AuthSession) RefreshToken() valueobjects.RefreshToken {
	return a.refreshToken
}

func (a *AuthSession) IsExpired() bool {
	return a.expiresAt.IsExpired()
}
