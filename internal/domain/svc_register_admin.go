package domain

import "time"

type IRegisterAdmin interface {
	Register(
		id UserID,
		email Email,
		pwd HashedPassword,
		defaultRole RoleName,
		now time.Time,
	) (*User, error)
}

type registerAdmin struct {
	registerPolicy IRegisterPolicy
}

func NewRegisterAdmin(
	registerPolicy IRegisterPolicy,
) IRegisterAdmin {
	return &registerAdmin{
		registerPolicy: registerPolicy,
	}
}

func (r *registerAdmin) Register(
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

	return user, nil
}
