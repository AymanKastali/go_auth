package use_cases

import (
	"log/slog"
	"time"

	"go_auth/internal/application/ports/security"
	"go_auth/internal/application/ports/use_cases"
	"go_auth/internal/domain/factories"
	"go_auth/internal/domain/ports/repositories"
)

type logoutUseCase struct {
	refreshRepo  repositories.RefreshTokenRepositoryPort
	tokenService security.TokenServicePort
	idFactory    factories.IDFactory
	logger       *slog.Logger
}

var _ use_cases.LogoutUserUseCasePort = (*logoutUseCase)(nil)

func NewLogoutUseCase(
	refreshRepo repositories.RefreshTokenRepositoryPort,
	tokenService security.TokenServicePort,
	idFactory factories.IDFactory,
	logger *slog.Logger,
) *logoutUseCase {
	return &logoutUseCase{
		refreshRepo:  refreshRepo,
		tokenService: tokenService,
		idFactory:    idFactory,
		logger:       logger,
	}
}

func (h *logoutUseCase) Logout(refreshToken string) error {
	h.logger.Info("Starting logout process")

	// 1. Validate token
	claims, err := h.tokenService.ValidateRefreshToken(refreshToken)
	if err != nil {
		h.logger.Warn("Failed to validate refresh token", "error", err)
		return err
	}
	h.logger.Info("Refresh token validated", "userID", claims.Subject, "tokenID", claims.JTI)

	// 2. Convert JTI string to TokenID VO
	tokenID, err := h.idFactory.TokenIDFromString(claims.JTI)
	if err != nil {
		h.logger.Error("Failed to convert token ID", "jti", claims.JTI, "error", err)
		return err
	}

	// 3. Revoke token in repository
	if err := h.refreshRepo.Revoke(tokenID, time.Now()); err != nil {
		h.logger.Error("Failed to revoke refresh token", "tokenID", tokenID, "error", err)
		return err
	}

	h.logger.Info("Logout successful", "userID", claims.Subject, "tokenID", tokenID)
	return nil
}
