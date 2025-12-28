package value_objects

type UserStatus string

const (
	UserPending  UserStatus = "PENDING"
	UserActive   UserStatus = "ACTIVE"
	UserInactive UserStatus = "INACTIVE"
)
