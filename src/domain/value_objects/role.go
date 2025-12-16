package valueobjects

type Role string

const (
	RoleOwner Role = "OWNER"
	RoleAdmin Role = "ADMIN"
	RoleUser  Role = "USER"
)
