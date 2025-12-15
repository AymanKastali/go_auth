package factories

import (
	valueobjects "go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type IDFactory struct{}

func (f *IDFactory) NewUserID() valueobjects.UserID {
	return valueobjects.UserID{Value: uuid.New()}
}

func (f *IDFactory) NewRoleID() valueobjects.RoleID {
	return valueobjects.RoleID{Value: uuid.New()}
}

func (f *IDFactory) NewPermissionID() valueobjects.PermissionID {
	return valueobjects.PermissionID{Value: uuid.New()}
}

func (f *IDFactory) NewTokenID() valueobjects.TokenID {
	return valueobjects.TokenID{Value: uuid.New()}
}

func (f *IDFactory) NewOrganizationID() valueobjects.OrganizationID {
	return valueobjects.OrganizationID{Value: uuid.New()}
}
