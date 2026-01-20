package factories

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type DefaultUserFactory struct {
	regPolicy ports.IUserRegistrationPolicy
	idSvc     ports.IIDService
	clockSvc  ports.IClockService
}

func NewDefaultUserFactory(
	regPolicy ports.IUserRegistrationPolicy,
	idSvc ports.IIDService,
	clockSvc ports.IClockService,
) *DefaultUserFactory {
	return &DefaultUserFactory{
		regPolicy: regPolicy,
		idSvc:     idSvc,
		clockSvc:  clockSvc,
	}
}

func (f *DefaultUserFactory) CreateNewUser(
	email valueobjects.Email,
	hashedPassword valueobjects.HashedPassword,
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

	now := f.clockSvc.Now().UTC()

	return aggregates.NewUser(
		userID,
		email,
		hashedPassword,
		valueobjects.UserActive,
		roles,
		now,
	)
}
