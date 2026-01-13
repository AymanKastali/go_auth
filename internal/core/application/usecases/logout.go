package usecases

import (
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
	"log/slog"
)

type logoutUseCase struct {
	refreshRepo dports.RefreshTokenRepositoryPort
	tokenSvc    aports.TokenServicePort
	uuidParser  interfaces.IUUIDParserService
	clock       interfaces.IClock
	logger      *slog.Logger
}

var _ aports.LogoutUseCasePort = (*logoutUseCase)(nil)

func NewLogoutUseCase(
	refreshRepo dports.RefreshTokenRepositoryPort,
	tokenSvc aports.TokenServicePort,
	uuidParser interfaces.IUUIDParserService,
	clock interfaces.IClock,
	logger *slog.Logger,
) aports.LogoutUseCasePort {
	return &logoutUseCase{
		refreshRepo: refreshRepo,
		tokenSvc:    tokenSvc,
		uuidParser:  uuidParser,
		clock:       clock,
		logger:      logger,
	}
}

func (uc *logoutUseCase) Execute(traceID string, refreshToken string) error {
	uc.logger.Info("Starting logout process", "trace_id", traceID)

	// 1. Validate Token
	claims, err := uc.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		uc.logger.Warn("Invalid refresh token provided for logout",
			"trace_id", traceID,
			"error", err)
		// tokenSvc returns derr.DomainError, so we map it
		return apperr.FromDomain(err, traceID)
	}

	// 2. Parse JTI from claims
	tokenID, err := uc.uuidParser.ParseTokenID(claims.JTI)
	if err != nil {
		uc.logger.Error("Token ID in claims is malformed",
			"trace_id", traceID,
			"jti", claims.JTI,
			"error", err)
		return apperr.BadRequest("malformed token identifier", traceID, err)
	}

	// 3. Revoke in Persistence
	err = uc.refreshRepo.Revoke(tokenID, uc.clock.NowUTC())
	if err != nil {
		uc.logger.Error("Failed to revoke refresh token",
			"trace_id", traceID,
			"tokenID", tokenID,
			"error", err)

		// This handles derr.CodeNotFound or database internal errors automatically
		return apperr.FromDomain(err, traceID)
	}

	uc.logger.Info("Logout successful",
		"trace_id", traceID,
		"userID", claims.Subject,
		"tokenID", tokenID)

	return nil
}
