package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
	"time"
)

type RefreshTokenRepositoryPort interface {
	// Save creates or updates a refresh token in the store.
	Save(token *entities.RefreshToken) error

	// GetByID fetches a refresh token by its unique identifier.
	// Returns nil, nil if the token is not found.
	GetByID(tokenID value_objects.TokenId) (*entities.RefreshToken, error)

	// GetByToken fetches a refresh token by its actual string value.
	// Returns nil, nil if the token is not found.
	GetByToken(tokenStr string) (*entities.RefreshToken, error)

	// Revoke marks a specific refresh token as revoked at the given time.
	Revoke(tokenID value_objects.TokenId, revokedAt time.Time) error

	// GetByUserID retrieves all refresh tokens associated with a specific user.
	GetByUserID(userID value_objects.UserId) ([]*entities.RefreshToken, error)

	IsRevoked(tokenID value_objects.TokenId) (bool, error)
}
