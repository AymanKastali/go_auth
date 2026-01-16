package usecases

import (
	"go_auth/internal/core/application/apperr"
	aports "go_auth/internal/core/application/ports"
	dports "go_auth/internal/core/domain/ports"
	"go_auth/internal/core/domain/valueobjects"
	"log/slog"
)

type logoutUseCase struct {
	refreshRepo dports.IRefreshTokenRepository
	tokenSvc    aports.ITokenService
	idSvc       dports.IIDService
	clock       dports.IClockService
	logger      *slog.Logger
}

func NewLogoutUseCase(
	refreshRepo dports.IRefreshTokenRepository,
	tokenSvc aports.ITokenService,
	idSvc dports.IIDService,
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

func (uc *logoutUseCase) Execute(traceID string, refreshToken string) error {
	uc.logger.Info("Starting logout process", "trace_id", traceID)

	// 1. Validate Token (Infrastructure check)
	claims, err := uc.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		uc.logger.Warn("Invalid refresh token provided for logout",
			"trace_id", traceID,
			"error", err)

		// If the token is already invalid/expired, logout is technically "done"
		// but we return Unauthorized to let the client know the session was already dead.
		return apperr.Unauthorized("session invalid or already expired", traceID, err)
	}

	tokenIDStr := claims.JTI

	// 2. Technical Validation
	if !uc.idSvc.IsValid(tokenIDStr) {
		return apperr.Validation("invalid token identifier format", traceID, map[string]any{"jti": tokenIDStr})
	}

	tokenID := valueobjects.ReconstituteTokenID(tokenIDStr)

	// 3. Revoke in Persistence (State Change)
	// We use the clock to ensure the revocation timestamp is consistent
	now := uc.clock.Now().UTC()
	err = uc.refreshRepo.Revoke(tokenID, now)
	if err != nil {
		uc.logger.Error("Failed to revoke refresh token",
			"trace_id", traceID,
			"token_id", tokenID.Value(),
			"error", err)

		// apperr.Map handles derr.CodeNotFound (already revoked)
		// or database connection failures automatically.
		return apperr.Map(err, traceID)
	}

	uc.logger.Info("Logout successful",
		"trace_id", traceID,
		"user_id", claims.Subject,
		"token_id", tokenID.Value())

	return nil
}
