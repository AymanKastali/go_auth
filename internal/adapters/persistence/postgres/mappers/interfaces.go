package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
)

type IUserMapper interface {
	ToDomain(m *models.User) (*aggregates.User, error)
	ToModel(a *aggregates.User) (*models.User, error)
}

type IRefreshTokenMapper interface {
	ToDomain(m *models.RefreshToken) (*entities.RefreshToken, error)
	ToModel(e *entities.RefreshToken) *models.RefreshToken
}

type IDeviceMapper interface {
	ToDomain(m *models.Device) (*entities.Device, error)
	ToModel(e *entities.Device) *models.Device
}

type IRoleMapper interface {
	ToDomain(m *models.Role) (*aggregates.Role, error)
	ToModel(a *aggregates.Role) (*models.Role, error)
}
