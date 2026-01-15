package usecases

import (
	"go_auth/internal/core/application/apperr"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/ports"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type logoutUseCase struct {
	refreshRepo dports.IRefreshTokenRepository
	tokenSvc    aports.ITokenService
	idSvc       ports.IIDService
	clock       dports.IClockService
	logger      *slog.Logger
}

func NewLogoutUseCase(
	refreshRepo dports.IRefreshTokenRepository,
	tokenSvc aports.ITokenService,
	idSvc ports.IIDService,
	clock dports.IClockService,
	logger *slog.Logger,
) *logoutUseCase {
	return &logoutUseCase{
		refreshRepo: refreshRepo,
		tokenSvc:    tokenSvc,
		idSvc:       idSvc,
		clock:       clock,
		logger:      logger,
	}
}

func (uc *logoutUseCase) Execute(requestID string, refreshToken string) error {
	uc.logger.Info("Starting logout process", "request_id", requestID)

	// 1. Validate Token
	claims, err := uc.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		uc.logger.Warn("Invalid refresh token provided for logout",
			"request_id", requestID,
			"error", err)
		// tokenSvc returns derr.DomainError, so we map it
		return apperr.FromDomain(err, requestID)
	}

	tokenIDStr := claims.JTI

	// 2. Parse JTI from claims
	if !uc.idSvc.IsValid(tokenIDStr) {
		return apperr.Invalid("invalid jti format", requestID, nil)
	}

	tokenID := valueobjects.ReconstituteTokenID(tokenIDStr)

	// 3. Revoke in Persistence
	err = uc.refreshRepo.Revoke(tokenID, uc.clock.Now().UTC())
	if err != nil {
		uc.logger.Error("Failed to revoke refresh token",
			"request_id", requestID,
			"tokenID", tokenID,
			"error", err)

		// This handles derr.CodeNotFound or database internal errors automatically
		return apperr.FromDomain(err, requestID)
	}

	uc.logger.Info("Logout successful",
		"request_id", requestID,
		"userID", claims.Subject,
		"tokenID", tokenID)

	return nil
}
