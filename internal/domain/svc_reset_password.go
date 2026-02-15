package domain

import "time"

type IResetPassword interface {
	Reset(user *User, recovery *RecoveryToken, newPassword ValidatedPassword, now time.Time) error
}

type resetPassword struct {
	passwordSvc IPasswordService
}

func NewResetPassword(passwordSvc IPasswordService) IResetPassword {
	return &resetPassword{passwordSvc: passwordSvc}
}

func (s *resetPassword) Reset(user *User, recovery *RecoveryToken, newPassword ValidatedPassword, now time.Time) error {
	if !recovery.IsValid(now) {
		return ErrRecoveryTokenInvalid
	}

	if !recovery.UserID().Equal(user.ID()) {
		return ErrInvalidRecoveryAttempt
	}

	newHash, err := s.passwordSvc.Hash(newPassword)
	if err != nil {
		return err
	}

	if err := user.UpdatePassword(newHash, now); err != nil {
		return err
	}
	return recovery.MarkAsUsed(now)
}
