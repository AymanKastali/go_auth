package valueobjects

type UserStatus string

const (
	UserPending  UserStatus = "pending"
	UserActive   UserStatus = "active"
	UserInactive UserStatus = "inactive"
)

func (s UserStatus) Value() string { return string(s) }

func (s UserStatus) IsValid() bool {
	switch s {
	case UserPending, UserActive, UserInactive:
		return true
	}
	return false
}
