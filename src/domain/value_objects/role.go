package value_objects

type Role string

const (
	RoleOwner Role = "OWNER"
	RoleAdmin Role = "ADMIN"
	RoleUser  Role = "USER"
)
