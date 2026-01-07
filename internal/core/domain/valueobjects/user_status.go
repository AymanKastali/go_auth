package valueobjects

type UserStatus string

const (
	UserPending  UserStatus = "pending"
	UserActive   UserStatus = "active"
	UserInactive UserStatus = "inactive"
)
