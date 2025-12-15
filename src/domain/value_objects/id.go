package valueobjects

import "github.com/google/uuid"

type UserID struct {
	Value uuid.UUID
}

type TokenID struct {
	Value uuid.UUID
}

type RoleID struct {
	Value uuid.UUID
}

type OrganizationID struct {
	Value uuid.UUID
}

type PermissionID struct {
	Value uuid.UUID
}

type MembershipID struct {
	Value uuid.UUID
}
