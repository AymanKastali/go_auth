package entities

import (
	"errors"
	value_objects "go_auth/src/domain/value_objects"
	"time"
)

type Membership struct {
	ID             value_objects.MembershipID
	UserID         value_objects.UserID
	OrganizationID value_objects.OrganizationID
	Role           value_objects.Role
	Status         value_objects.MembershipStatus
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
}

func (u *Membership) touch() {
	u.UpdatedAt = time.Now().UTC()
}

func (m *Membership) ChangeRole(role value_objects.Role) error {
	if role == "" {
		return errors.New("role cannot be empty")
	}
	if m.Role == role {
		return errors.New("role is already assigned")
	}
	m.Role = role
	m.touch()
	return nil
}

// Revoke revokes the membership
func (m *Membership) Revoke() error {
	if m.Status == value_objects.MembershipRevoked {
		return errors.New("membership is already revoked")
	}
	m.Status = value_objects.MembershipRevoked
	m.touch()
	return nil
}

// Activate activates the membership
func (m *Membership) Activate() error {
	if m.Status == value_objects.MembershipActive {
		return errors.New("membership is already active")
	}
	m.Status = value_objects.MembershipActive
	m.touch()
	return nil
}

// Suspend suspends the membership
func (m *Membership) Suspend() error {
	if m.Status == value_objects.MembershipSuspended {
		return errors.New("membership is already suspended")
	}
	m.Status = value_objects.MembershipSuspended
	m.touch()
	return nil
}

// IsActive checks if the membership is active
func (m *Membership) IsActive() bool {
	return m.Status == value_objects.MembershipActive
}

// MarkDeleted soft deletes the membership
func (m *Membership) MarkDeleted() {
	now := time.Now().UTC()
	m.DeletedAt = &now
	m.touch()
}
