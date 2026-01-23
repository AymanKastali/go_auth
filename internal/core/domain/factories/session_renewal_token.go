package factories

import (
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/policies"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type defaultSessionRenewalTokenFactory struct {
	tokenGenerator ports.IRandomTokenGenerator
	tokenHasher    ports.ITokenHasherService
	idSvc          ports.IIDService
	policy         policies.SessionRenewalTokenPolicy
}

func NewDefaultSessionRenewalTokenFactory(
	tokenGenerator ports.IRandomTokenGenerator,
	tokenHasher ports.ITokenHasherService,
	idSvc ports.IIDService,
	policy policies.SessionRenewalTokenPolicy,
) *defaultSessionRenewalTokenFactory {
	return &defaultSessionRenewalTokenFactory{
		tokenGenerator: tokenGenerator,
		tokenHasher:    tokenHasher,
		idSvc:          idSvc,
		policy:         policy,
	}
}

func (f *defaultSessionRenewalTokenFactory) New(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	now valueobjects.Timepoint,
) (*entities.SessionRenewalToken, valueobjects.SessionRenewalRawToken, error) {
	emptySessionRenewalToken := valueobjects.SessionRenewalRawToken{}
	tokenID, err := valueobjects.NewSessionRenewalTokenID(f.idSvc.Generate())
	if err != nil {
		return nil, emptySessionRenewalToken, err
	}

	rawSecret, err := f.tokenGenerator.Generate()
	if err != nil {
		return nil, emptySessionRenewalToken, err
	}

	rawToken, err := valueobjects.NewSessionRenewalRawToken(tokenID, rawSecret)
	if err != nil {
		return nil, emptySessionRenewalToken, err
	}

	hashed, err := f.tokenHasher.Hash(rawSecret)
	if err != nil {
		return nil, emptySessionRenewalToken, err
	}

	expiresAt := now.Add(f.policy.Lifetime)

	sessionRenewalToken, err := entities.NewSessionRenewalToken(
		tokenID,
		userID,
		deviceID,
		hashed,
		expiresAt,
		now,
	)
	if err != nil {
		return nil, emptySessionRenewalToken, err
	}

	return sessionRenewalToken, rawToken, nil
}
