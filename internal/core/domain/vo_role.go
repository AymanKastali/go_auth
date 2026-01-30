package domain

import "strings"

var ZeroRole = Role{}

// --- Role ---
type Role struct{ name string }

var (
	RoleSuperAdmin = Role{name: "super_admin"}
	RoleAdmin      = Role{name: "admin"}
	RoleEditor     = Role{name: "editor"}
	RoleModerator  = Role{name: "moderator"}
	RoleMember     = Role{name: "member"}
	RolePremium    = Role{name: "premium"}
	RoleGuest      = Role{name: "guest"}
	RolePartner    = Role{name: "partner"}
)

var nameToRole = map[string]Role{
	"super_admin": RoleSuperAdmin,
	"admin":       RoleAdmin,
	"editor":      RoleEditor,
	"moderator":   RoleModerator,
	"member":      RoleMember,
	"premium":     RolePremium,
	"guest":       RoleGuest,
	"partner":     RolePartner,
}

func NewRole(name string) (Role, error) {
	canonicalName := strings.ToLower(strings.TrimSpace(name))
	role, exists := nameToRole[canonicalName]
	if !exists {
		return ZeroRole, ErrRoleNotRecognized
	}
	return role, nil
}
func ReconstituteRole(name string) Role {
	role, exists := nameToRole[name]
	if !exists {
		return Role{name: name}
	}
	return role
}
func (r Role) Name() string          { return r.name }
func (r Role) Equal(other Role) bool { return r.name == other.name }
