package domain

import "time"

type IRegisterMember interface {
	Register(
		id UserID,
		email Email,
		pwd HashedPassword,
		defaultRole RoleName,
		now time.Time,
	) (*User, error)
}

type registerMember struct {
	registerPolicy   IRegisterPolicy
	activationPolicy IActivationPolicy
}

func NewRegisterMember(
	registerPolicy IRegisterPolicy,
	activationPolicy IActivationPolicy,
) IRegisterMember {
	return &registerMember{
		registerPolicy:   registerPolicy,
		activationPolicy: activationPolicy,
	}
}

func (r *registerMember) Register(
	id UserID,
	email Email,
	pwd HashedPassword,
	defaultRole RoleName,
	now time.Time,
) (*User, error) {
	if err := r.registerPolicy.Validate(email); err != nil {
		return nil, err
	}

	user, err := NewUser(id, email, pwd, now)
	if err != nil {
		return nil, err
	}

	if err := user.AssignRole(defaultRole, now); err != nil {
		return nil, err
	}

	if r.activationPolicy.RequiresEmailActivation() {
		if err := user.Deactivate(now); err != nil {
			return nil, err
		}
	}

	return user, nil
}
