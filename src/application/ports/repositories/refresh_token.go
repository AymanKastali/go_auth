package repositories

import "time"

type RefreshTokenRepositoryPort interface {
	Revoke(jti string) error
	IsRevoked(jti string) (bool, error)
	Save(jti string, userID string, token string, expiresAt time.Time) error
}
