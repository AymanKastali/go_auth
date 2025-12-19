package entities

import (
	"errors"
	valueobjects "go_auth/src/domain/value_objects"
	"time"
)

type Organization struct {
	ID          valueobjects.OrganizationID
	Name        string
	OwnerUserID valueobjects.UserID
	Status      valueobjects.OrganizationStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

func (o *Organization) touch() {
	o.UpdatedAt = time.Now().UTC()
}

func (o *Organization) Rename(name string) error {
	if o.Status != valueobjects.OrgActive {
		return errors.New("organization is not active")
	}
	if name == "" {
		return errors.New("invalid name")
	}
	o.Name = name
	o.touch()
	return nil
}

func (o *Organization) Suspend() error {
	if o.Status != valueobjects.OrgActive {
		return errors.New("organization not active")
	}

	o.Status = valueobjects.OrgSuspended
	o.touch()
	return nil
}

func (o *Organization) Reactivate() error {
	if o.Status != valueobjects.OrgSuspended {
		return errors.New("organization not suspended")
	}

	o.Status = valueobjects.OrgActive
	o.touch()
	return nil
}

func (o *Organization) MarkDeleted() {
	now := time.Now().UTC()
	o.DeletedAt = &now
	o.touch()
}
