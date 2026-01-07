package use_cases

import (
	"log/slog"
	"time"

	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports/repositories"
	"go_auth/internal/core/application/ports/security"
	"go_auth/internal/core/domain/valueobjects"
)

type LogoutUseCase struct {
	refreshRepo  repositories.RefreshTokenRepositoryPort
	tokenService security.TokenServicePort
	logger       *slog.Logger
}

func NewLogoutUseCase(
	refreshRepo repositories.RefreshTokenRepositoryPort,
	tokenService security.TokenServicePort,
	logger *slog.Logger,
) *LogoutUseCase {
	return &LogoutUseCase{
		refreshRepo:  refreshRepo,
		tokenService: tokenService,
		logger:       logger,
	}
}

func (h *LogoutUseCase) Execute(refreshToken string) error {
	h.logger.Info("Starting logout process")

	// 1. Validate token string
	claims, err := h.tokenService.ValidateRefreshToken(refreshToken)
	if err != nil {
		h.logger.Warn("Invalid refresh token provided for logout", "error", err)
		// Map token validation errors to Unauthorized
		return apperr.NewUnauthorizedErr("invalid or expired session")
	}

	// 2. Convert JTI (from claims) to TokenID Value Object
	tokenID, err := valueobjects.TokenIDFromString(claims.JTI)
	if err != nil {
		h.logger.Error("Token ID in claims is malformed", "jti", claims.JTI, "error", err)
		return apperr.MapDomainErr(err)
	}

	// 3. Revoke token in repository
	// The repository now returns apperr.NotFoundErr if the token ID doesn't exist
	// or apperr.InternalErr if the database is down.
	err = h.refreshRepo.Revoke(tokenID, time.Now().UTC())
	if err != nil {
		h.logger.Error("Failed to revoke refresh token in DB", "tokenID", tokenID, "error", err)
		return err // Already an apperr type
	}

	h.logger.Info("Execute successful", "userID", claims.Subject, "tokenID", tokenID)
	return nil
}
