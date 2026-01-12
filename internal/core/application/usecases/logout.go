package usecases

import (
	"errors"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/interfaces"
	aports "go_auth/internal/core/application/ports"
	"go_auth/internal/core/domain/derr"
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

func (uc *logoutUseCase) Execute(refreshToken string) error {
	uc.logger.Info("Starting logout process")

	claims, err := uc.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		uc.logger.Warn("Invalid refresh token provided for logout", "error", err)
		return apperr.Unauthorized(err)
	}

	tokenID, err := uc.uuidParser.ParseTokenID(claims.JTI)
	if err != nil {
		uc.logger.Error("Token ID in claims is malformed", "jti", claims.JTI, "error", err)
		return apperr.Validation(err)
	}

	err = uc.refreshRepo.Revoke(tokenID, uc.clock.NowUTC())
	if err != nil {
		// 1. Check if it's a Domain Error
		var dErr derr.DomainError
		if errors.As(err, &dErr) {
			// 2. If the operation failed because it wasn't found, logout is effectively done
			if dErr.Op() == derr.OpNotFound {
				uc.logger.Warn("Token already revoked or non-existent", "tokenID", tokenID.Value())
				return apperr.NotFound(dErr)
			}
			// Other domain violations (Conflict, etc.)
			return apperr.Conflict(dErr)
		}

		// 3. Technical failures (DB down, etc.)
		uc.logger.Error("Failed to revoke refresh token", "tokenID", tokenID, "error", err)
		return apperr.Internal(err)
	}

	uc.logger.Info("Logout successful", "userID", claims.Subject, "tokenID", tokenID)
	return nil
}
