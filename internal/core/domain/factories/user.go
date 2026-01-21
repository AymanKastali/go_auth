package factories

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type defaultUserFactory struct {
	regPolicy ports.IUserRegistrationPolicy
	idSvc     ports.IIDService
}

func NewDefaultUserFactory(
	regPolicy ports.IUserRegistrationPolicy,
	idSvc ports.IIDService,
) *defaultUserFactory {
	return &defaultUserFactory{
		regPolicy: regPolicy,
		idSvc:     idSvc,
	}
}

func (f *defaultUserFactory) New(
	email valueobjects.Email,
	hashedPassword valueobjects.HashedPassword,
	now valueobjects.Timepoint,
) (*aggregates.User, error) {
	if err := f.regPolicy.Validate(email); err != nil {
		return nil, err
	}

	roles, err := f.regPolicy.DefaultRoles()
	if err != nil {
		return nil, err
	}

	userID, err := valueobjects.NewUserID(f.idSvc.Generate())
	if err != nil {
		return nil, err
	}

	return aggregates.NewUser(
		userID,
		email,
		hashedPassword,
		valueobjects.UserActive,
		roles,
		now,
	)
}
