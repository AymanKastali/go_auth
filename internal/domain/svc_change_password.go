package domain

import "time"

type IChangePassword interface {
	Change(user *User, oldPass string, newPass ValidatedPassword, now time.Time) error
}

type changePassword struct {
	passwordSvc IPasswordService
}

func NewChangePassword(
	passwordSvc IPasswordService,
) IChangePassword {
	return &changePassword{
		passwordSvc: passwordSvc,
	}
}

func (s *changePassword) Change(user *User, oldPass string, newPass ValidatedPassword, now time.Time) error {
	if !s.passwordSvc.Compare(oldPass, user.HashedPassword()) {
		return ErrAuthenticationFailed
	}

	newHash, err := s.passwordSvc.Hash(newPass)
	if err != nil {
		return err
	}

	return user.UpdatePassword(newHash, now)
}
