package ports

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type UserRepositoryPort interface {
	Save(user *aggregates.User) error
	Update(user *aggregates.User) error
	GetByID(id valueobjects.UserID) (*aggregates.User, error)
	GetByEmail(email valueobjects.Email) (*aggregates.User, error)
}

type RoleRepositoryPort interface {
	Save(role *aggregates.Role) error
	GetByID(id valueobjects.RoleID) (*aggregates.Role, error)
	GetByName(name string) (*aggregates.Role, error)
	GetAll() ([]*aggregates.Role, error)
}

type RefreshTokenRepositoryPort interface {
	Save(token *entities.RefreshToken) error
	GetByID(tokenID valueobjects.TokenID) (*entities.RefreshToken, error)
	GetByToken(tokenStr string) (*entities.RefreshToken, error)
	Revoke(tokenID valueobjects.TokenID, revokedAt time.Time) error
	GetByUserID(userID valueobjects.UserID) ([]*entities.RefreshToken, error)
	IsRevoked(tokenID valueobjects.TokenID) (bool, error)
	RevokeByDeviceID(userID valueobjects.UserID, deviceID valueobjects.DeviceID, revokedAt time.Time) error
}

type DeviceRepositoryPort interface {
	GetByID(deviceID valueobjects.DeviceID) (*entities.Device, error)
	Upsert(device *entities.Device) error
	Revoke(deviceID valueobjects.DeviceID, revokedAt time.Time) error
	GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error)
}
