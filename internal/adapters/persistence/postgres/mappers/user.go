package mappers

import (
	"go_auth/internal/adapters/persistence/postgres/models"
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type UserMapper struct{}

func NewUserMapper() *UserMapper { return &UserMapper{} }

func (m *UserMapper) ToDomain(model *models.User) *aggregates.User {
	if model == nil {
		return nil
	}

	// Pure assignment. No validation logic lives here anymore.
	roleIDs := make([]valueobjects.RoleID, len(model.Roles))
	for i, r := range model.Roles {
		roleIDs[i] = valueobjects.ReconstituteRoleID(r.ID)
	}

	var deletedAt *valueobjects.Timepoint
	if model.DeletedAt != nil {
		tp := valueobjects.ReconstituteTimepoint(*model.DeletedAt)
		deletedAt = &tp
	}

	return aggregates.ReconstituteUser(
		valueobjects.ReconstituteUserID(model.ID),
		valueobjects.ReconstituteEmail(model.Email),
		valueobjects.ReconstituteHashedPassword(model.HashedPassword),
		valueobjects.UserStatus(model.Status),
		roleIDs,
		valueobjects.ReconstituteTimepoint(model.CreatedAt),
		valueobjects.ReconstituteTimepoint(model.UpdatedAt),
		deletedAt,
	)
}

func (m *UserMapper) ToModel(aggregate *aggregates.User) *models.User {
	if aggregate == nil {
		return nil
	}

	roles := make([]models.Role, len(aggregate.RoleIDs()))
	for i, rid := range aggregate.RoleIDs() {
		roles[i] = models.Role{ID: rid.Value()}
	}

	var deletedAtPtr *time.Time
	if aggregate.DeletedAt() != nil {
		t := aggregate.DeletedAt().Value()
		deletedAtPtr = &t
	}

	return &models.User{
		ID:             aggregate.ID().Value(),
		Email:          aggregate.Email().Value(),
		HashedPassword: aggregate.HashedPassword().Value(),
		Status:         aggregate.Status().Value(),
		Roles:          roles,
		CreatedAt:      aggregate.CreatedAt().Value(),
		UpdatedAt:      aggregate.UpdatedAt().Value(),
		DeletedAt:      deletedAtPtr,
	}
}
