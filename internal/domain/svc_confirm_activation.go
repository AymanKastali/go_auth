package domain

import "time"

type IConfirmActivation interface {
	Confirm(user *User, activation *ActivationToken, now time.Time) error
}

type confirmActivation struct{}

func NewConfirmActivation() IConfirmActivation {
	return &confirmActivation{}
}

func (s *confirmActivation) Confirm(user *User, activation *ActivationToken, now time.Time) error {
	if activation.IsExpired(now) {
		return ErrActivationTokenExpired
	}
	if activation.IsUsed() {
		return ErrActivationTokenAlreadyUsed
	}
	if !activation.IsValid(now) {
		return ErrActivationTokenInvalid
	}

	if !activation.UserID().Equal(user.ID()) {
		return ErrActivationTokenInvalid
	}

	if user.IsActive() {
		return ErrUserAlreadyActive
	}

	if err := user.Activate(now); err != nil {
		return err
	}
	return activation.MarkAsUsed(now)
}
