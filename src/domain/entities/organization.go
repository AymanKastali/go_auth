package entities

import (
	"errors"
	value_objects "go_auth/src/domain/value_objects"
	"time"
)

type Organization struct {
	ID          value_objects.OrganizationID
	Name        string
	OwnerUserID value_objects.UserID
	Status      value_objects.OrganizationStatus
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

func (o *Organization) touch() {
	o.UpdatedAt = time.Now().UTC()
}

func (o *Organization) Rename(name string) error {
	if o.Status != value_objects.OrgActive {
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
	if o.Status != value_objects.OrgActive {
		return errors.New("organization not active")
	}

	o.Status = value_objects.OrgSuspended
	o.touch()
	return nil
}

func (o *Organization) Reactivate() error {
	if o.Status != value_objects.OrgSuspended {
		return errors.New("organization not suspended")
	}

	o.Status = value_objects.OrgActive
	o.touch()
	return nil
}

func (o *Organization) MarkDeleted() {
	now := time.Now().UTC()
	o.DeletedAt = &now
	o.touch()
}
