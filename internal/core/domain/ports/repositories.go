package ports

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type IUserRepository interface {
	Create(a *aggregates.User) error
	Update(a *aggregates.User) error
	GetByID(id valueobjects.UserID) (*aggregates.User, error)
	GetByEmail(email valueobjects.Email) (*aggregates.User, error)
	ExistsByEmail(email valueobjects.Email) (bool, error)
}

type IDeviceRepository interface {
	GetByID(deviceID valueobjects.DeviceID) (*entities.Device, error)
	Upsert(e *entities.Device) error
	GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error)
}

type IRoleRepository interface {
	Save(a *aggregates.Role) error
	GetByID(id valueobjects.RoleID) (*aggregates.Role, error)
	GetByName(name string) (*aggregates.Role, error)
	GetAll() ([]*aggregates.Role, error)
}

type IRenewalTokenRepository interface {
	Save(token *entities.RenewalToken) error
	FindByHash(hash valueobjects.HashedToken) (*entities.RenewalToken, error)
	FindByID(id valueobjects.TokenID) (*entities.RenewalToken, error)
	FindByUser(userID valueobjects.UserID) ([]*entities.RenewalToken, error)
	FindByUserAndDevice(userID valueobjects.UserID, deviceID valueobjects.DeviceID) ([]*entities.RenewalToken, error)
}
