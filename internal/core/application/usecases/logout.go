package usecases

import (
	"context"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type LogoutUseCase struct {
	refreshRepo ports.IRefreshTokenRepository
	clockSvc    ports.IClockService
	tokenHasher ports.ITokenHasherService
}

func NewLogoutUseCase(
	repo ports.IRefreshTokenRepository,
	clockSvc ports.IClockService,
	tokenHasher ports.ITokenHasherService,
) *LogoutUseCase {
	return &LogoutUseCase{
		refreshRepo: repo,
		clockSvc:    clockSvc,
		tokenHasher: tokenHasher,
	}
}

func (uc *LogoutUseCase) Execute(ctx context.Context, rawToken string) error {
	now, err := uc.clockSvc.Now()
	if err != nil {
		return apperr.Map(err)
	}
	tokenVO, err := valueobjects.ParseRawRefreshToken(rawToken)
	if err != nil {
		return apperr.Validation("Invalid refresh token", nil)
	}

	tokenEntity, err := uc.refreshRepo.FindByID(tokenVO.TokenID())
	if err != nil {
		return apperr.Map(err)
	}

	if tokenEntity == nil {
		return nil
	}

	valid, err := uc.tokenHasher.Compare(tokenVO.Secret(), tokenEntity.HashedToken())
	if err != nil {
		return apperr.Map(err)
	}
	if !valid {
		return apperr.Unauthorized("Invalid refresh token", nil)
	}

	if err := tokenEntity.Revoke(now); err != nil {
		return apperr.Map(err)
	}

	return uc.refreshRepo.Save(tokenEntity)
}
