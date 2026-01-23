package ports

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type IUserRepository interface {
	Save(a *aggregates.User) error
	Update(a *aggregates.User) error
	GetByID(id valueobjects.UserID) (*aggregates.User, error)
	GetByEmail(email valueobjects.Email) (*aggregates.User, error)
	ExistsByEmail(email valueobjects.Email) (bool, error)
}

type IDeviceRepository interface {
	GetByID(id valueobjects.DeviceID) (*entities.Device, error)
	GetByFingerprint(fingerprint valueobjects.DeviceFingerprint) (*entities.Device, error)
	Upsert(e *entities.Device) error
	GetByUserID(userID valueobjects.UserID) ([]*entities.Device, error)
}

type IRoleRepository interface {
	Save(a *aggregates.Role) error
	GetByID(id valueobjects.RoleID) (*aggregates.Role, error)
	GetByName(name string) (*aggregates.Role, error)
	GetAll() ([]*aggregates.Role, error)
	GetByIDs(ids []valueobjects.RoleID) ([]*aggregates.Role, error)
}

type ISessionRenewalTokenRepository interface {
	Save(token *entities.SessionRenewalToken) error
	SaveMany(tokens []*entities.SessionRenewalToken) error
	FindByID(id valueobjects.SessionRenewalRawTokenID) (*entities.SessionRenewalToken, error)
	FindByUser(userID valueobjects.UserID) ([]*entities.SessionRenewalToken, error)
	FindByUserAndDevice(userID valueobjects.UserID, deviceID valueobjects.DeviceID) ([]*entities.SessionRenewalToken, error)
}
