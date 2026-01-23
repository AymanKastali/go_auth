package usecases

import (
	"context"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type LogoutUseCase struct {
	sessionRenewalRepo ports.ISessionRenewalTokenRepository
	clockSvc           ports.IClockService
	tokenHasher        ports.ITokenHasherService
}

func NewLogoutUseCase(
	repo ports.ISessionRenewalTokenRepository,
	clockSvc ports.IClockService,
	tokenHasher ports.ITokenHasherService,
) *LogoutUseCase {
	return &LogoutUseCase{
		sessionRenewalRepo: repo,
		clockSvc:           clockSvc,
		tokenHasher:        tokenHasher,
	}
}

func (uc *LogoutUseCase) Execute(ctx context.Context, rawToken string) error {
	now, err := uc.clockSvc.Now()
	if err != nil {
		return apperr.Map(err)
	}
	tokenVO, err := valueobjects.ParseSessionRenewalRawToken(rawToken)
	if err != nil {
		return apperr.Validation("Invalid session renewal token", nil)
	}

	tokenEntity, err := uc.sessionRenewalRepo.FindByID(tokenVO.ID())
	if err != nil {
		return apperr.Map(err)
	}

	if tokenEntity == nil {
		return nil
	}

	valid, err := uc.tokenHasher.Compare(tokenVO.Secret(), tokenEntity.SessionRenewalHashedToken())
	if err != nil {
		return apperr.Map(err)
	}
	if !valid {
		return apperr.Unauthorized("Invalid session renewal token", nil)
	}

	if err := tokenEntity.Revoke(now); err != nil {
		return apperr.Map(err)
	}

	return uc.sessionRenewalRepo.Save(tokenEntity)
}
