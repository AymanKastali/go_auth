package repositories

import (
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type RefreshTokenRepositoryPort interface {
	Save(token *entities.RefreshToken) error

	GetByID(tokenID valueobjects.TokenID) (*entities.RefreshToken, error)

	GetByToken(tokenStr string) (*entities.RefreshToken, error)

	Revoke(tokenID valueobjects.TokenID, revokedAt time.Time) error

	GetByUserID(userID valueobjects.UserID) ([]*entities.RefreshToken, error)

	IsRevoked(tokenID valueobjects.TokenID) (bool, error)

	RevokeByDeviceID(userID valueobjects.UserID, deviceID valueobjects.DeviceID, revokedAt time.Time) error
}
