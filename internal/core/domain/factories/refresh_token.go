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
	emptyRawRefreshToken := valueobjects.RawRefreshToken{}

	tokenID, err := valueobjects.NewTokenID(f.idSvc.Generate())
	if err != nil {
		return nil, emptyRawRefreshToken, err
	}

	rawToken, err := f.tokenGenerator.Generate(32)
	if err != nil {
		return nil, emptyRawRefreshToken, err
	}

	rawRefreshToken, err := valueobjects.NewRawRefreshToken(rawToken)
	if err != nil {
		return nil, emptyRawRefreshToken, err
	}

	hashedToken, err := f.tokenHasher.Hash(rawToken)
	if err != nil {
		return nil, emptyRawRefreshToken, err
	}

	refreshToken, err := entities.NewRefreshToken(
		tokenID,
		userID,
		deviceID,
		hashedToken,
		expiresAt,
		now,
	)
	return refreshToken, rawRefreshToken, err
}
