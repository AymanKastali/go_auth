package factories

import (
	"errors"
	"go_auth/src/domain/entities"
	"time"
)

type role string

const (
	RoleAdmin role = "admin"
	RoleUser  role = "user"
)

type RoleFactory struct{}

func (f *RoleFactory) New(
	name string,
	description string,
	initialPermissions []entities.Permission,
) (*entities.Role, error) {
	if name == "" {
		return nil, errors.New("role name cannot be empty")
	}
	now := time.Now().UTC()
	idFactory := IDFactory{}
	return &entities.Role{
		ID:          idFactory.NewRoleID(),
		Name:        name,
		Description: description,
		Permissions: initialPermissions,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func (f *RoleFactory) NewDefaultUserRole() (*entities.Role, error) {
	now := time.Now().UTC()
	idFactory := IDFactory{}
	return &entities.Role{
		ID:          idFactory.NewRoleID(),
		Name:        string(RoleUser),
		Description: "Default User Role",
		Permissions: []entities.Permission{},
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}
