package valueobjects

import "slices"

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

type Roles []Role

func (r Roles) Contains(role Role) bool {
	return slices.Contains(r, role)
}

func (r Roles) ToStrings() []string {
	out := make([]string, len(r))
	for i, role := range r {
		out[i] = string(role)
	}
	return out
}
