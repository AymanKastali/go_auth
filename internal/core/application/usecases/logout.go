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
}

func NewLogoutUseCase(
	repo ports.IRefreshTokenRepository,
	clockSvc ports.IClockService,
) *LogoutUseCase {
	return &LogoutUseCase{
		refreshRepo: repo,
		clockSvc:    clockSvc,
	}
}

func (uc *LogoutUseCase) Execute(ctx context.Context, rawToken string) error {
	now := uc.clockSvc.Now()
	tokenVO, err := valueobjects.NewRawRefreshToken(rawToken)
	if err != nil {
		return apperr.Map(err)
	}

	tokenEntity, err := uc.refreshRepo.FindByRawToken(tokenVO)
	if err != nil {
		return apperr.Map(err)
	}
	if tokenEntity == nil {
		return nil
	}

	if err := tokenEntity.Revoke(now); err != nil {
		return apperr.Map(err)
	}

	return uc.refreshRepo.Save(tokenEntity)
}
