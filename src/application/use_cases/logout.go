package use_cases

import (
	"time"

	"go_auth/src/application/ports/security"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
)

type LogoutUseCase struct {
	refreshRepo  repositories.RefreshTokenRepositoryPort
	tokenService security.TokenServicePort
	idFactory    factories.IDFactory
}

func NewLogoutUseCase(
	refreshRepo repositories.RefreshTokenRepositoryPort,
	tokenService security.TokenServicePort,
	idFactory factories.IDFactory,
) *LogoutUseCase {
	return &LogoutUseCase{
		refreshRepo:  refreshRepo,
		tokenService: tokenService,
		idFactory:    idFactory,
	}
}

func (h *LogoutUseCase) Execute(refreshToken string) error {
	// 1. Validate token
	claims, err := h.tokenService.ValidateRefreshToken(refreshToken)
	if err != nil {
		return err
	}

	// 2. Convert JTI string to TokenId VO
	tokenID, err := h.idFactory.TokenIDFromString(claims.JTI)
	if err != nil {
		return err
	}

	// 3. Revoke token in repository
	return h.refreshRepo.Revoke(tokenID, time.Now())
}
