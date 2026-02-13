package domain

import "context"

type IResolvePermissions interface {
	Resolve(ctx context.Context, roles []RoleName) ([]Permission, error)
}

type resolvePermissions struct {
	roleRepo IRoleRepository
}

func NewResolvePermissions(roleRepo IRoleRepository) IResolvePermissions {
	return &resolvePermissions{roleRepo: roleRepo}
}

func (r *resolvePermissions) Resolve(ctx context.Context, roles []RoleName) ([]Permission, error) {
	seen := make(map[string]struct{})
	var permissions []Permission

	for _, roleName := range roles {
		role, err := r.roleRepo.FindByName(ctx, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			continue
		}
		for _, p := range role.Permissions() {
			key := p.String()
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				permissions = append(permissions, p)
			}
		}
	}

	return permissions, nil
}
