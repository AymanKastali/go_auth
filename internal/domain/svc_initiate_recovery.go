package domain

import "time"

type IInitiateRecovery interface {
	Initiate(user *User, now time.Time) (string, *RecoveryToken, error)
}

type initiateRecovery struct {
	tokenSvc       ITokenService
	idGen          IIDGenerator
	recoveryPolicy IRecoveryPolicy
}

func NewInitiateRecovery(
	tokenSvc ITokenService,
	idGen IIDGenerator,
	recoveryPolicy IRecoveryPolicy,
) IInitiateRecovery {
	return &initiateRecovery{
		tokenSvc:       tokenSvc,
		idGen:          idGen,
		recoveryPolicy: recoveryPolicy,
	}
}

func (s *initiateRecovery) Initiate(user *User, now time.Time) (string, *RecoveryToken, error) {
	if !user.IsActive() {
		return "", nil, ErrUserInactive
	}

	rawToken, err := s.tokenSvc.Generate()
	if err != nil {
		return "", nil, err
	}

	hashedToken, err := s.tokenSvc.HashRecoveryToken(rawToken)
	if err != nil {
		return "", nil, err
	}

	expirationTime := now.Add(s.recoveryPolicy.GetRecoveryTokenLifetime())

	id, err := s.idGen.GenerateRecoveryTokenID()
	if err != nil {
		return "", nil, err
	}

	recoveryToken, err := NewRecoveryToken(
		id,
		user.ID(),
		hashedToken,
		expirationTime,
		now,
	)
	if err != nil {
		return "", nil, err
	}

	return rawToken, recoveryToken, nil
}
