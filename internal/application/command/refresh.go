package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IRefreshTokenHandler interface {
	Handle(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error)
}

type refreshTokenHandler struct {
	userRepo      domain.IUserRepository
	sessionRepo   domain.ISessionRepository
	authSvc       domain.IAuthenticationService
	accessManager domain.IAccessManager
	clock         domain.IClock
	dispatcher    IEventDispatcher
}

func NewRefreshTokenHandler(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	authSvc domain.IAuthenticationService,
	accessManager domain.IAccessManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IRefreshTokenHandler {
	return &refreshTokenHandler{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		authSvc:       authSvc,
		accessManager: accessManager,
		clock:         clock,
		dispatcher:    dispatcher,
	}
}

func (h *refreshTokenHandler) Handle(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error) {
	logger := application.GetLogger(ctx).With(slog.String("handler", "RefreshToken"))

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

	now := h.clock.Now()
	user, session, err := h.authSvc.RefreshSession(ctx, raw, fp, now)
	if err != nil {
		logger.Warn("refresh_session_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	accessToken, accessExpiry, err := h.accessManager.GrantImmediateAccess(ctx, user, session.ID(), now)
	if err != nil {
		logger.Error("access_grant_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	if err := h.sessionRepo.Save(ctx, session); err != nil {
		logger.Error("session_save_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	h.dispatcher.Dispatch(ctx, session.CollectEvents())

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
