package ports

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
)

type IUserMapper interface {
	ToDomain(model *models.User) *aggregates.User
	ToModel(aggregate *aggregates.User) *models.User
}

type IDeviceMapper interface {
	ToDomain(model *models.Device) *entities.Device
	ToModel(entity *entities.Device) *models.Device
}

type ISessionRenewalTokenMapper interface {
	ToDomain(model *models.SessionRenewalToken) *entities.SessionRenewalToken
	ToModel(entity *entities.SessionRenewalToken) *models.SessionRenewalToken
}

type IRoleMapper interface {
	ToDomain(model *models.Role) *aggregates.Role
	ToModel(entity *aggregates.Role) *models.Role
}
