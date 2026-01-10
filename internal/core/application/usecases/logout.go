package usecases

import (
	"log/slog"
	"time"

	"go_auth/internal/core/application/apperr"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
)

type logoutUseCase struct {
	refreshRepo dports.RefreshTokenRepositoryPort
	tokenSvc    aports.TokenServicePort
	logger      *slog.Logger
}

var _ aports.LogoutUseCasePort = (*logoutUseCase)(nil)

func NewLogoutUseCase(
	refreshRepo dports.RefreshTokenRepositoryPort,
	tokenSvc aports.TokenServicePort,
	logger *slog.Logger,
) aports.LogoutUseCasePort {
	return &logoutUseCase{
		refreshRepo: refreshRepo,
		tokenSvc:    tokenSvc,
		logger:      logger,
	}
}

func (h *logoutUseCase) Execute(refreshToken string) error {
	h.logger.Info("Starting logout process")

	// 1. Validate token string
	claims, err := h.tokenSvc.ValidateRefreshToken(refreshToken)
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
