package domain

import "strings"

var ZeroRoleName = RoleName{}
var ZeroRoleID = RoleID{}

// --- RoleID ---
type RoleID struct{ value string }

func NewRoleID(value string) (RoleID, error) {
	if value == "" {
		return ZeroRoleID, ErrRoleIDRequired
	}
	return RoleID{value: value}, nil
}
func ReconstituteRoleID(value string) RoleID  { return RoleID{value: value} }
func (vo RoleID) String() string              { return vo.value }
func (vo RoleID) IsEmpty() bool               { return vo.value == "" }
func (vo RoleID) Equal(other RoleID) bool     { return vo.value == other.value }

// --- RoleName ---
type RoleName struct{ name string }

var (
	RoleSuperAdmin = RoleName{name: "super_admin"}
	RoleAdmin      = RoleName{name: "admin"}
	RoleEditor     = RoleName{name: "editor"}
	RoleModerator  = RoleName{name: "moderator"}
	RoleMember     = RoleName{name: "member"}
	RolePremium    = RoleName{name: "premium"}
	RoleGuest      = RoleName{name: "guest"}
	RolePartner    = RoleName{name: "partner"}
)

var nameToRoleName = map[string]RoleName{
	"super_admin": RoleSuperAdmin,
	"admin":       RoleAdmin,
	"editor":      RoleEditor,
	"moderator":   RoleModerator,
	"member":      RoleMember,
	"premium":     RolePremium,
	"guest":       RoleGuest,
	"partner":     RolePartner,
}

func NewRoleName(name string) (RoleName, error) {
	canonicalName := strings.ToLower(strings.TrimSpace(name))
	role, exists := nameToRoleName[canonicalName]
	if !exists {
		return ZeroRoleName, ErrRoleNotRecognized
	}
	return role, nil
}
func ReconstituteRoleName(name string) RoleName {
	role, exists := nameToRoleName[name]
	if !exists {
		return RoleName{name: name}
	}
	return role
}
func (r RoleName) Name() string              { return r.name }
func (r RoleName) Equal(other RoleName) bool { return r.name == other.name }
func (r RoleName) IsEmpty() bool             { return r.name == "" }

// AllRoleNames returns all predefined role names.
func AllRoleNames() []RoleName {
	return []RoleName{
		RoleSuperAdmin, RoleAdmin, RoleEditor, RoleModerator,
		RoleMember, RolePremium, RoleGuest, RolePartner,
	}
}
