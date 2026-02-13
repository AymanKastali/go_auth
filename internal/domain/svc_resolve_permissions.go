package domain

type IResolvePermissions interface {
	Resolve(roles []*Role) []Permission
}

type resolvePermissions struct{}

func NewResolvePermissions() IResolvePermissions {
	return &resolvePermissions{}
}

func (r *resolvePermissions) Resolve(roles []*Role) []Permission {
	seen := make(map[string]struct{})
	var permissions []Permission

	for _, role := range roles {
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

	return permissions
}
