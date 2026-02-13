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
	sessionRepo domain.ISessionRepository
	refresher   domain.IRefreshSession
	granter     domain.IGrantAccess
	clock       domain.IClock
	dispatcher  IEventDispatcher
}

func NewRefreshTokenHandler(
	sessionRepo domain.ISessionRepository,
	refresher domain.IRefreshSession,
	granter domain.IGrantAccess,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IRefreshTokenHandler {
	return &refreshTokenHandler{
		sessionRepo: sessionRepo,
		refresher:   refresher,
		granter:     granter,
		clock:       clock,
		dispatcher:  dispatcher,
	}
}

func (h *refreshTokenHandler) Handle(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error) {
	logger := application.GetLogger(ctx).With(slog.String("handler", "RefreshToken"))

	if cmd.RefreshToken == "" {
		logger.Warn("invalid_refresh_token")
		return ZeroLoginResponse, domain.ErrTokenInvalid
	}

	fp, err := domain.NewDeviceFingerprint(cmd.Fingerprint)
	if err != nil {
		logger.Warn("invalid_fingerprint", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	now := h.clock.Now()
	user, session, newRawToken, err := h.refresher.Refresh(ctx, cmd.RefreshToken, fp, now)
	if err != nil {
		if session != nil {
			_ = h.sessionRepo.Save(ctx, session)
			h.dispatcher.Dispatch(ctx, session.CollectEvents())
		}
		logger.Warn("refresh_session_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	accessToken, accessExpiry, err := h.granter.Grant(ctx, user, session.ID(), now)
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
		RefreshToken:       newRawToken,
		RefreshTokenExpiry: session.Expiry().Time().String(),
	}, nil
}
