package repositories

import (
	"go_auth/src/domain/entities"
	"go_auth/src/domain/value_objects"
	"time"
)

type RefreshTokenRepositoryPort interface {
	Save(token *entities.RefreshToken) error

	GetByID(tokenID value_objects.TokenID) (*entities.RefreshToken, error)

	GetByToken(tokenStr string) (*entities.RefreshToken, error)

	Revoke(tokenID value_objects.TokenID, revokedAt time.Time) error

	GetByUserID(userID value_objects.UserID) ([]*entities.RefreshToken, error)

	IsRevoked(tokenID value_objects.TokenID) (bool, error)

	RevokeByDeviceID(userID value_objects.UserID, deviceID value_objects.DeviceID, revokedAt time.Time) error
}
