package postgres

import (
	"go_auth/internal/core/domain"
)

func toUserModel(u *domain.User) UserModel {
	userRoles := make([]UserRoleModel, len(u.Roles()))
	for i, r := range u.Roles() {
		userRoles[i] = UserRoleModel{
			UserID:   u.ID().String(),
			RoleName: r.Name(),
		}
	}

	return UserModel{
		ID:           u.ID().String(),
		Email:        u.Email().String(),
		PasswordHash: u.HashedPassword().String(),
		IsActive:     u.IsActive(),
		UserRoles:    userRoles,
		RegisteredAt: u.RegisteredAt().Time(),
	}
}

func toUserDomain(m UserModel) (*domain.User, error) {
	uid := domain.ReconstituteUserID(m.ID)
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
		m.DeletedAt != nil,
		domain.ReconstituteTimepoint(m.RegisteredAt),
	), nil
}
