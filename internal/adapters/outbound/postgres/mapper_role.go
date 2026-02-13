package postgres

import (
	"go_auth/internal/domain"
)

func toRoleModel(r *domain.Role) RoleModel {
	permModels := make([]PermissionModel, len(r.Permissions()))
	for i, p := range r.Permissions() {
		permModels[i] = PermissionModel{
			Resource: p.Resource(),
			Action:   p.Action(),
		}
	}

	return RoleModel{
		ULID:        r.ID().String(),
		Name:        r.Name().Name(),
		Description: r.Description(),
		Permissions: permModels,
	}
}

func toRoleDomain(m RoleModel) *domain.Role {
	permissions := make([]domain.Permission, len(m.Permissions))
	for i, p := range m.Permissions {
		permissions[i] = domain.ReconstitutePermission(p.Resource, p.Action)
	}

	return domain.ReconstituteRole(
		domain.ReconstituteRoleID(m.ULID),
		domain.ReconstituteRoleName(m.Name),
		m.Description,
		permissions,
	)
}
