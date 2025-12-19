package entities

import (
	"errors"
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

type Membership struct {
	ID             valueobjects.MembershipID
	UserID         valueobjects.UserID
	OrganizationID valueobjects.OrganizationID
	Role           valueobjects.Role
	Status         valueobjects.MembershipStatus
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      *time.Time
}

func (u *Membership) touch() {
	u.UpdatedAt = time.Now().UTC()
}

func (m *Membership) ChangeRole(role valueobjects.Role) error {
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
	if m.Status == valueobjects.MembershipRevoked {
		return errors.New("membership is already revoked")
	}
	m.Status = valueobjects.MembershipRevoked
	m.touch()
	return nil
}

// Activate activates the membership
func (m *Membership) Activate() error {
	if m.Status == valueobjects.MembershipActive {
		return errors.New("membership is already active")
	}
	m.Status = valueobjects.MembershipActive
	m.touch()
	return nil
}

// Suspend suspends the membership
func (m *Membership) Suspend() error {
	if m.Status == valueobjects.MembershipSuspended {
		return errors.New("membership is already suspended")
	}
	m.Status = valueobjects.MembershipSuspended
	m.touch()
	return nil
}

// IsActive checks if the membership is active
func (m *Membership) IsActive() bool {
	return m.Status == valueobjects.MembershipActive
}

// MarkDeleted soft deletes the membership
func (m *Membership) MarkDeleted() {
	now := time.Now().UTC()
	m.DeletedAt = &now
	m.touch()
}
