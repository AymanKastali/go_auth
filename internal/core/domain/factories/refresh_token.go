package factories

import (
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type defaultRefreshTokenFactory struct {
	tokenGenerator ports.IRandomTokenGenerator
	tokenHasher    ports.ITokenHasherService
	idSvc          ports.IIDService
}

func NewDefaultRefreshTokenFactory(
	tokenGenerator ports.IRandomTokenGenerator,
	tokenHasher ports.ITokenHasherService,
	idSvc ports.IIDService,
) *defaultRefreshTokenFactory {
	return &defaultRefreshTokenFactory{
		tokenGenerator: tokenGenerator,
		tokenHasher:    tokenHasher,
		idSvc:          idSvc,
	}
}

func (f *defaultRefreshTokenFactory) New(
	userID valueobjects.UserID,
	deviceID valueobjects.DeviceID,
	expiresAt valueobjects.Timepoint,
	now valueobjects.Timepoint,
) (*entities.RefreshToken, valueobjects.RawRefreshToken, error) {

	tokenID, err := valueobjects.NewTokenID(f.idSvc.Generate())
	if err != nil {
		return nil, valueobjects.RawRefreshToken{}, err
	}

	rawSecret, err := f.tokenGenerator.Generate(32)
	if err != nil {
		return nil, valueobjects.RawRefreshToken{}, err
	}

	rawRefreshToken, err := valueobjects.NewRawRefreshToken(tokenID, rawSecret)
	if err != nil {
		return nil, valueobjects.RawRefreshToken{}, err
	}

	hashed := f.tokenHasher.Hash(rawSecret)

	refreshToken, err := entities.NewRefreshToken(
		tokenID,
		userID,
		deviceID,
		hashed,
		expiresAt,
		now,
	)
	if err != nil {
		return nil, valueobjects.RawRefreshToken{}, err
	}

	return refreshToken, rawRefreshToken, nil
}
