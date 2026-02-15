package domain

import "time"

type IInitiateActivation interface {
	Initiate(user *User, now time.Time) (string, *ActivationToken, error)
}

type initiateActivation struct {
	tokenSvc         ITokenService
	idGen            IIDGenerator
	activationPolicy IActivationPolicy
}

func NewInitiateActivation(
	tokenSvc ITokenService,
	idGen IIDGenerator,
	activationPolicy IActivationPolicy,
) IInitiateActivation {
	return &initiateActivation{
		tokenSvc:         tokenSvc,
		idGen:            idGen,
		activationPolicy: activationPolicy,
	}
}

func (s *initiateActivation) Initiate(user *User, now time.Time) (string, *ActivationToken, error) {
	rawToken, err := s.tokenSvc.Generate()
	if err != nil {
		return "", nil, err
	}

	hashedToken, err := s.tokenSvc.HashActivationToken(rawToken)
	if err != nil {
		return "", nil, err
	}

	expirationTime := now.Add(s.activationPolicy.GetActivationTokenLifetime())

	id, err := s.idGen.GenerateActivationTokenID()
	if err != nil {
		return "", nil, err
	}

	activationToken, err := NewActivationToken(
		id,
		user.ID(),
		hashedToken,
		expirationTime,
		now,
	)
	if err != nil {
		return "", nil, err
	}

	return rawToken, activationToken, nil
}
