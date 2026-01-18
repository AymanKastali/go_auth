package usecases

import (
	"context"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/dto"
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
}

func NewLogoutUseCase(
	refreshRepo dports.IRefreshTokenRepository,
	tokenSvc aports.ITokenService,
	idSvc dports.IIDService,
	clock dports.IClockService,
) *logoutUseCase {
	return &logoutUseCase{
		refreshRepo: refreshRepo,
		tokenSvc:    tokenSvc,
		idSvc:       idSvc,
		clock:       clock,
	}
}

func (uc *logoutUseCase) Execute(
	c context.Context,
	refreshToken string,
) error {
	req := dto.GetRequestContext(c)
	l := req.Logger

	l.Info("Executing user logout")

	claims, err := uc.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		l.Warn("Logout failed: invalid or expired refresh token", slog.Any("error", err))
		return apperr.Unauthorized("session invalid or already expired", err)
	}

	tokenIDStr := claims.JTI
	if !uc.idSvc.IsValid(tokenIDStr) {
		l.Warn("Logout failed: malformed token identifier", slog.String("jti", tokenIDStr))
		return apperr.Validation("invalid token identifier format", map[string]any{"jti": tokenIDStr})
	}

	tokenID := valueobjects.ReconstituteTokenID(tokenIDStr)
	now := uc.clock.Now().UTC()

	l.Debug("Revoking session", slog.String("token_id", tokenID.Value()))

	if err := uc.refreshRepo.Revoke(tokenID, now); err != nil {
		l.Error("Database error during token revocation",
			slog.String("token_id", tokenID.Value()),
			slog.Any("error", err),
		)
		return apperr.Map(err)
	}

	l.Info("Logout successful",
		slog.String("user_id", claims.Subject),
		slog.String("token_id", tokenID.Value()),
	)

	return nil
}
