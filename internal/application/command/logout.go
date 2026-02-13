package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type ILogoutHandler interface {
	Handle(ctx context.Context, cmd LogoutCommand) error
}

type logoutHandler struct {
	sessionRepo domain.ISessionRepository
	clock       domain.IClock
	dispatcher  IEventDispatcher
}

func NewLogoutHandler(
	sessionRepo domain.ISessionRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) ILogoutHandler {
	return &logoutHandler{
		sessionRepo: sessionRepo,
		clock:       clock,
		dispatcher:  dispatcher,
	}
}

func (h *logoutHandler) Handle(ctx context.Context, cmd LogoutCommand) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "Logout"))

	_, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		return err
	}

	sid, err := domain.NewSessionID(cmd.SessionID)
	if err != nil {
		return err
	}

	session, err := h.sessionRepo.FindByID(ctx, sid)
	if err != nil {
		logger.Error("session_lookup_failed", slog.Any("error", err))
		return err
	}
	if session == nil {
		return domain.ErrSessionNotFound
	}

	now := h.clock.Now()
	if err := session.Revoke(now); err != nil {
		logger.Warn("logout_rejected_by_aggregate",
			slog.String("session_id", sid.String()),
			slog.Any("error", err),
		)
		return err
	}

	if err := h.sessionRepo.Save(ctx, session); err != nil {
		logger.Error("session_save_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, session.CollectEvents())

	logger.Info("logout_success", slog.String("session_id", sid.String()))

	return nil
}
