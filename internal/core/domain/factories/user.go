package factories

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type defaultUserFactory struct {
	regPolicy    ports.IUserRegistrationPolicy
	pwdPolicy    ports.IPasswordPolicyService
	idSvc        ports.IIDService
	pwdHasherSvc ports.IPasswordHasherService
}

func NewDefaultUserFactory(
	regPolicy ports.IUserRegistrationPolicy,
	pwdPolicy ports.IPasswordPolicyService,
	idSvc ports.IIDService,
	pwdHasherSvc ports.IPasswordHasherService,
) *defaultUserFactory {
	return &defaultUserFactory{
		regPolicy:    regPolicy,
		pwdPolicy:    pwdPolicy,
		idSvc:        idSvc,
		pwdHasherSvc: pwdHasherSvc,
	}
}

func (f *defaultUserFactory) New(
	email valueobjects.Email,
	rawPwd valueobjects.RawPassword,
	now valueobjects.Timepoint,
) (*aggregates.User, error) {
	if err := f.pwdPolicy.Validate(rawPwd); err != nil {
		return nil, err
	}

	if err := f.regPolicy.Validate(email); err != nil {
		return nil, err
	}

	hashedPwd, err := f.pwdHasherSvc.Hash(rawPwd)
	if err != nil {
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
		hashedPwd,
		valueobjects.UserActive,
		roles,
		now,
	)
}
