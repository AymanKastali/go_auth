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
	clockSvc    dports.IClockService
}

func NewLogoutUseCase(
	refreshRepo dports.IRefreshTokenRepository,
	tokenSvc aports.ITokenService,
	idSvc dports.IIDService,
	clockSvc dports.IClockService,
) *logoutUseCase {
	return &logoutUseCase{
		refreshRepo: refreshRepo,
		tokenSvc:    tokenSvc,
		idSvc:       idSvc,
		clockSvc:    clockSvc,
	}
}

func (uc *logoutUseCase) Execute(
	c context.Context,
	refreshToken string,
) error {
	auth, ok := dto.GetAuthCtx(c)
	if !ok {
		slog.Error("logout called without auth context")
		return apperr.Internal("authentication context missing", nil)
	}
	l := auth.Logger

	l.Info("Executing user logout", slog.String("user_id", auth.UserID))

	// 1. Validate the Refresh Token string/signature
	claims, err := uc.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		l.Warn("Logout failed: invalid refresh token", slog.Any("error", err))
		return apperr.Unauthorized("session invalid or expired", err)
	}

	// 2. Security Cross-Check: User Identity
	if claims.Subject != auth.UserID {
		l.Warn("Logout fraud attempt: user mismatch",
			slog.String("authenticated_user", auth.UserID),
			slog.String("token_owner", claims.Subject),
		)
		return apperr.Forbidden("action not permitted", nil)
	}

	// 3. Fetch the actual record from DB
	tokenID := valueobjects.ReconstituteTokenID(claims.JTI)
	tokenEntity, err := uc.refreshRepo.GetByID(tokenID)
	if err != nil {
		return apperr.Map(err)
	}

	// FIX 1: If token doesn't exist in DB, it's not a valid session to logout
	if tokenEntity == nil {
		l.Warn("Logout failed: token not found in database", slog.String("token_id", tokenID.Value()))
		return apperr.NotFound("Session", tokenID.Value())
	}

	// FIX 2: Security Cross-Check: Device Ownership
	// Prevents revoking a session that belongs to a different device
	currentDeviceID := valueobjects.ReconstituteDeviceID(auth.DeviceID)
	if err := tokenEntity.BelongsTo(currentDeviceID); err != nil {
		l.Warn("Logout fraud attempt: device mismatch",
			slog.String("request_device", auth.DeviceID),
			slog.String("token_device", tokenEntity.DeviceID().Value()),
		)
		return apperr.Forbidden("this session does not belong to your current device", nil)
	}

	// 4. Revoke and Persist
	currentTime := uc.clockSvc.Now().UTC()
	if err := tokenEntity.Revoke(currentTime); err != nil {
		l.Error("Error during token revocation", slog.Any("error", err))
		return apperr.Map(err)
	}

	if err := uc.refreshRepo.Save(tokenEntity); err != nil {
		l.Error("Database error during token revocation", slog.Any("error", err))
		return apperr.Map(err)
	}

	l.Info("Logout successful")
	return nil
}
