package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// --- Refresh Token Use Case ---
type refreshTokenUseCase struct {
	userRepo      domain.IUserRepository
	authSvc       domain.IAuthenticationService
	accessManager domain.IAccessManager
	clock         domain.IClock
}

func NewRefreshTokenUseCase(
	userRepo domain.IUserRepository,
	authSvc domain.IAuthenticationService,
	accessManager domain.IAccessManager,
	clock domain.IClock,
) IRefreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepo:      userRepo,
		authSvc:       authSvc,
		accessManager: accessManager,
		clock:         clock,
	}
}

func (uc *refreshTokenUseCase) Execute(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "RefreshToken"))

	// 1. VO Conversion
	raw, err := domain.NewRawToken(cmd.RefreshToken)
	if err != nil {
		logger.Warn("invalid_refresh_token", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	fp, err := domain.NewDeviceFingerprint(cmd.Fingerprint)
	if err != nil {
		logger.Warn("invalid_fingerprint", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 2. Domain Service Coordination
	now := uc.clock.Now()
	user, session, err := uc.authSvc.RefreshSession(ctx, raw, fp, now)
	if err != nil {
		logger.Warn("refresh_session_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 3. Access Manager Coordination
	accessToken, accessExpiry, err := uc.accessManager.GrantImmediateAccess(user, session.ID(), now)
	if err != nil {
		logger.Error("access_grant_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 4. Atomic Persistence
	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	logger.Info("refresh_token_success",
		slog.String("user_id", user.ID().String()),
		slog.String("session_id", session.ID().String()),
	)

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  accessExpiry.String(),
		RefreshToken:       cmd.RefreshToken,
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}
