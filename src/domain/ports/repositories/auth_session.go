package repositories

import (
	"go_auth/src/domain/aggregates"
)

type AuthSessionRepository interface {
	Save(session *aggregates.AuthSession) error
	// FindByAccessToken(token valueobjects.AccessToken) (*aggregates.AuthSession, error)
	// Delete(tokenID valueobjects.TokenID) error
}
