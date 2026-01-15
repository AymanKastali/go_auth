package ports

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type IUserRepository interface {
	Create(a *aggregates.User) error
	Update(a *aggregates.User) error
	GetByID(id valueobjects.UserID) (*aggregates.User, error)
	GetByEmail(email valueobjects.Email) (*aggregates.User, error)
}

type IDeviceRepository interface {
	GetByID(deviceID valueobjects.DeviceID) (*entities.Device, error)
	Upsert(e *entities.Device) error
	Revoke(deviceID valueobjects.DeviceID, revokedAt time.Time) error
	GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error)
}

type IRoleRepository interface {
	Save(a *aggregates.Role) error
	GetByID(id valueobjects.RoleID) (*aggregates.Role, error)
	GetByName(name string) (*aggregates.Role, error)
	GetAll() ([]*aggregates.Role, error)
}

type IRefreshTokenRepository interface {
	Save(e *entities.RefreshToken) error
	GetByID(tokenID valueobjects.TokenID) (*entities.RefreshToken, error)
	GetByToken(tokenStr string) (*entities.RefreshToken, error)
	Revoke(tokenID valueobjects.TokenID, revokedAt time.Time) error
	GetByUserID(userID valueobjects.UserID) ([]*entities.RefreshToken, error)
	IsRevoked(tokenID valueobjects.TokenID) (bool, error)
	RevokeByDeviceID(userID valueobjects.UserID, deviceID valueobjects.DeviceID, revokedAt time.Time) error
}
