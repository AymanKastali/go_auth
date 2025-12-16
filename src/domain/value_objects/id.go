package valueobjects

import "github.com/google/uuid"

type UserID struct {
	Value uuid.UUID
}

func (id UserID) IsZero() bool {
	return id.Value == uuid.Nil
}

type TokenID struct {
	Value uuid.UUID
}

func (id TokenID) IsZero() bool {
	return id.Value == uuid.Nil
}

type RoleID struct {
	Value uuid.UUID
}

func (id RoleID) IsZero() bool {
	return id.Value == uuid.Nil
}

type OrganizationID struct {
	Value uuid.UUID
}

func (id OrganizationID) IsZero() bool {
	return id.Value == uuid.Nil
}

type PermissionID struct {
	Value uuid.UUID
}

func (id PermissionID) IsZero() bool {
	return id.Value == uuid.Nil
}

type MembershipID struct {
	Value uuid.UUID
}

func (id MembershipID) IsZero() bool {
	return id.Value == uuid.Nil
}
