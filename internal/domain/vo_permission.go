package domain

import "strings"

// Permission represents a granular access control entry in "resource:action" format.
type Permission struct {
	resource string
	action   string
}

func NewPermission(value string) (Permission, error) {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return Permission{}, ErrPermissionInvalid
	}
	return Permission{resource: parts[0], action: parts[1]}, nil
}

func ReconstitutePermission(resource, action string) Permission {
	return Permission{resource: resource, action: action}
}

func (p Permission) Resource() string { return p.resource }
func (p Permission) Action() string   { return p.action }
func (p Permission) String() string   { return p.resource + ":" + p.action }
func (p Permission) IsEmpty() bool    { return p.resource == "" && p.action == "" }

func (p Permission) Equal(other Permission) bool {
	return p.resource == other.resource && p.action == other.action
}
