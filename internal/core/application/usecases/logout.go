package usecases

import (
	"context"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/domain/ports"
)

type LogoutUseCase struct {
	renewalRepo ports.IRenewalTokenRepository
	clock       ports.IClockService
	hasher      ports.ITokenHasherService
}

func NewLogoutUseCase(
	repo ports.IRenewalTokenRepository,
	clock ports.IClockService,
	hasher ports.ITokenHasherService,
) *LogoutUseCase {
	return &LogoutUseCase{
		renewalRepo: repo,
		clock:       clock,
		hasher:      hasher,
	}
}

func (uc *LogoutUseCase) Execute(ctx context.Context, rawToken string) error {
	now := uc.clock.Now().UTC()

	hashed, err := uc.hasher.Hash(rawToken)
	if err != nil {
		return apperr.Map(err)
	}

	tokenEntity, err := uc.renewalRepo.FindByHash(hashed)
	if err != nil {
		return apperr.Map(err)
	}
	if tokenEntity == nil {
		return nil
	}

	if err := tokenEntity.Revoke(now); err != nil {
		return apperr.Map(err)
	}

	return uc.renewalRepo.Save(tokenEntity)
}
