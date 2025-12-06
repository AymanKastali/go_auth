package repositories

import (
	"go_auth/src/domain/entities"

	"github.com/google/uuid"
)

type TokenSessionRepository interface {
	Save(session *entities.TokenSession) error
	Get(jti uuid.UUID) (*entities.TokenSession, error)
	Revoke(jti uuid.UUID) error
}
