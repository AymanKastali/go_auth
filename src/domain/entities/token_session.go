// domain/auth/entities/token_session.go
package entities

import (
	"time"

	"github.com/google/uuid"
)

type TokenSession struct {
	JTI       uuid.UUID
	UserID    uuid.UUID
	IssuedAt  time.Time
	ExpiresAt time.Time
	Revoked   bool
}

func NewTokenSession(jti uuid.UUID, userID uuid.UUID, expiresAt time.Time) *TokenSession {
	return &TokenSession{
		JTI:       jti,
		UserID:    userID,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: expiresAt,
		Revoked:   false,
	}
}

func (t *TokenSession) Revoke() {
	t.Revoked = true
}

func (t *TokenSession) IsValid() bool {
	return !t.Revoked && time.Now().UTC().Before(t.ExpiresAt)
}
