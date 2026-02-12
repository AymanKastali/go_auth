package postgres

import (
	"go_auth/internal/domain"

	"gorm.io/gorm"
)

func toUserModel(u *domain.User) UserModel {
	userRoles := make([]UserRoleModel, len(u.Roles()))
	for i, r := range u.Roles() {
		userRoles[i] = UserRoleModel{
			RoleName: r.Name(),
		}
	}

	model := UserModel{
		ULID:         u.ID().String(),
		Email:        u.Email().String(),
		PasswordHash: u.HashedPassword().String(),
		IsActive:     u.IsActive(),
		UserRoles:    userRoles,
	}

	if u.IsDeleted() {
		model.DeletedAt = gorm.DeletedAt{Valid: true}
	}

	return model
}

func toUserDomain(m UserModel) (*domain.User, error) {
	uid := domain.ReconstituteUserID(m.ULID)
	email := domain.ReconstituteEmail(m.Email)
	passwordHash := domain.ReconstituteHashedPassword(m.PasswordHash)

	roles := make([]domain.RoleName, len(m.UserRoles))
	for i, ur := range m.UserRoles {
		roles[i] = domain.ReconstituteRoleName(ur.RoleName)
	}

	return domain.ReconstituteUser(
		uid,
		email,
		passwordHash,
		m.IsActive,
		roles,
		m.DeletedAt.Valid,
		domain.ReconstituteTimepoint(m.CreatedAt),
	), nil
}
