package domain

type IVerifyCredentials interface {
	Verify(user *User, rawPassword string) error
}

type verifyCredentials struct {
	passwordSvc IPasswordService
}

func NewVerifyCredentials(passwordSvc IPasswordService) IVerifyCredentials {
	return &verifyCredentials{passwordSvc: passwordSvc}
}

func (s *verifyCredentials) Verify(user *User, rawPassword string) error {
	if !s.passwordSvc.Compare(rawPassword, user.HashedPassword()) {
		return ErrAuthenticationFailed
	}
	if !user.IsActive() {
		return ErrUserInactive
	}
	return nil
}
