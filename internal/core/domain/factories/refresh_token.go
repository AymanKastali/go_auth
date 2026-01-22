package factories

import (
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/policies"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type defaultRefreshTokenFactory struct {
	tokenGenerator ports.IRandomTokenGenerator
	tokenHasher    ports.ITokenHasherService
	idSvc          ports.IIDService
	policy         policies.RefreshTokenPolicy
}

func NewDefaultRefreshTokenFactory(
	tokenGenerator ports.IRandomTokenGenerator,
	tokenHasher ports.ITokenHasherService,
	idSvc ports.IIDService,
	policy policies.RefreshTokenPolicy,
) *defaultRefreshTokenFactory {
	return &defaultRefreshTokenFactory{
		tokenGenerator: tokenGenerator,
		tokenHasher:    tokenHasher,
		idSvc:          idSvc,
		policy:         policy,
	}
}

func (f *defaultRefreshTokenFactory) New(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	now valueobjects.Timepoint,
) (*entities.RefreshToken, valueobjects.RawRefreshToken, error) {
	emptyRefreshToken := valueobjects.RawRefreshToken{}
	tokenID, err := valueobjects.NewTokenID(f.idSvc.Generate())
	if err != nil {
		return nil, emptyRefreshToken, err
	}

	rawSecret, err := f.tokenGenerator.Generate()
	if err != nil {
		return nil, emptyRefreshToken, err
	}

	rawRefreshToken, err := valueobjects.NewRawRefreshToken(tokenID, rawSecret)
	if err != nil {
		return nil, emptyRefreshToken, err
	}

	hashed, err := f.tokenHasher.Hash(rawSecret)
	if err != nil {
		return nil, emptyRefreshToken, err
	}

	expiresAt := now.Add(f.policy.Lifetime)

	refreshToken, err := entities.NewRefreshToken(
		tokenID,
		userID,
		deviceID,
		hashed,
		expiresAt,
		now,
	)
	if err != nil {
		return nil, emptyRefreshToken, err
	}

	return refreshToken, rawRefreshToken, nil
}
