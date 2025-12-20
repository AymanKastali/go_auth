package value_objects

type MembershipStatus string

const (
	MembershipActive    MembershipStatus = "ACTIVE"
	MembershipRevoked   MembershipStatus = "REVOKED"
	MembershipSuspended MembershipStatus = "SUSPENDED"
)
