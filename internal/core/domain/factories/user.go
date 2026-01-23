package factories

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type UserFactory struct {
	idSvc ports.IIDService
}

func NewDefaultUserFactory(
	idSvc ports.IIDService,
) *UserFactory {
	return &UserFactory{
		idSvc: idSvc,
	}
}

func (f *UserFactory) New(
	email valueobjects.Email,
	hashed valueobjects.HashedPassword,
	roles []valueobjects.RoleID,
	now valueobjects.Timepoint,
) (*aggregates.User, error) {
	userID, err := valueobjects.NewUserID(f.idSvc.Generate())
	if err != nil {
		return nil, err
	}

	return aggregates.NewUser(
		userID,
		email,
		hashed,
		valueobjects.UserActive,
		roles,
		now,
	)
}
