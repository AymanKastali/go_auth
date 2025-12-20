package factories

import (
	value_objects "go_auth/src/domain/value_objects"

	"github.com/google/uuid"
)

type IDFactory struct{}

func (f *IDFactory) NewUserID() value_objects.UserID {
	return value_objects.UserID{Value: uuid.New()}
}

func (f *IDFactory) NewRoleID() value_objects.RoleID {
	return value_objects.RoleID{Value: uuid.New()}
}

func (f *IDFactory) NewPermissionID() value_objects.PermissionID {
	return value_objects.PermissionID{Value: uuid.New()}
}

func (f *IDFactory) NewTokenID() value_objects.TokenID {
	return value_objects.TokenID{Value: uuid.New()}
}

func (f *IDFactory) NewOrganizationID() value_objects.OrganizationID {
	return value_objects.OrganizationID{Value: uuid.New()}
}

func (f *IDFactory) NewMembershipID() value_objects.MembershipID {
	return value_objects.MembershipID{Value: uuid.New()}
}
