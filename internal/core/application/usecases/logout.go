package usecases

import (
	"log/slog"

	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
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

func (uc *logoutUseCase) Execute(refreshToken string) error {
	uc.logger.Info("Starting logout process")

	// 1. Validate token string
	claims, err := uc.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		uc.logger.Warn("Invalid refresh token provided for logout", "error", err)
		// Map token validation errors to Unauthorized
		return apperr.NewUnauthorizedErr("invalid or expired session")
	}

	// 2. Convert JTI (from claims) to TokenID Value Object
	tokenID, err := uc.uuidParser.ParseTokenID(claims.JTI)
	if err != nil {
		uc.logger.Error("Token ID in claims is malformed", "jti", claims.JTI, "error", err)
		return apperr.MapDomainErr(err)
	}

	// 3. Revoke token in repository
	// The repository now returns apperr.NotFoundErr if the token ID doesn't exist
	// or apperr.InternalErr if the database is down.
	err = uc.refreshRepo.Revoke(tokenID, uc.clock.NowUTC())
	if err != nil {
		uc.logger.Error("Failed to revoke refresh token in DB", "tokenID", tokenID, "error", err)
		return err // Already an apperr type
	}

	uc.logger.Info("Execute successful", "userID", claims.Subject, "tokenID", tokenID)
	return nil
}
