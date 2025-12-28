package use_cases

import (
	"time"

	"go_auth/src/application/ports/security"
	"go_auth/src/domain/factories"
	"go_auth/src/domain/ports/repositories"
)

type logoutUseCase struct {
	refreshRepo  repositories.RefreshTokenRepositoryPort
	tokenService security.TokenServicePort
	idFactory    factories.IDFactory
}

func NewLogoutUseCase(
	refreshRepo repositories.RefreshTokenRepositoryPort,
	tokenService security.TokenServicePort,
	idFactory factories.IDFactory,
) *logoutUseCase {
	return &logoutUseCase{
		refreshRepo:  refreshRepo,
		tokenService: tokenService,
		idFactory:    idFactory,
	}
}

func (h *logoutUseCase) Execute(refreshToken string) error {
	// 1. Validate token
	claims, err := h.tokenService.ValidateRefreshToken(refreshToken)
	if err != nil {
		return err
	}

	// 2. Convert JTI string to TokenId VO
	tokenId, err := h.idFactory.TokenIDFromString(claims.JTI)
	if err != nil {
		return err
	}

	// 3. Revoke token in repository
	return h.refreshRepo.Revoke(tokenId, time.Now())
}
