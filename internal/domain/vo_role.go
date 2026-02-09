package domain

import (
	"regexp"
	"strings"
)

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

var roleNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{1,49}$`)

func NewRoleName(name string) (RoleName, error) {
	canonicalName := strings.ToLower(strings.TrimSpace(name))
	if !roleNameRegex.MatchString(canonicalName) {
		return ZeroRoleName, ErrRoleNameInvalid
	}
	return RoleName{name: canonicalName}, nil
}
func ReconstituteRoleName(name string) RoleName {
	return RoleName{name: name}
}
func (r RoleName) Name() string              { return r.name }
func (r RoleName) Equal(other RoleName) bool { return r.name == other.name }
func (r RoleName) IsEmpty() bool             { return r.name == "" }
