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

func (m *Membership) ChangeRole(role valueobjects.Role) {
	m.Role = role
	m.touch()
}

func (m *Membership) Revoke() error {
	if m.Status == valueobjects.MembershipRevoked {
		return errors.New("Membership is already revoked")
	}
	m.Status = valueobjects.MembershipRevoked
	m.touch()
	return nil
}
