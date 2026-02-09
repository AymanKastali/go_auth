package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

type logoutUseCase struct {
	sessionRepo domain.ISessionRepository
	clock       domain.IClock
	dispatcher  IEventDispatcher
}

func NewLogoutUseCase(
	sessionRepo domain.ISessionRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) ILogoutUseCase {
	return &logoutUseCase{
		sessionRepo: sessionRepo,
		clock:       clock,
		dispatcher:  dispatcher,
	}
}

func (uc *logoutUseCase) Execute(ctx context.Context, cmd LogoutCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "Logout"))

	// 1. VO Conversion (Fail Fast)
	_, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		logger.Warn("invalid_user_id", slog.Any("error", err))
		return err
	}

	sid, err := domain.NewSessionID(cmd.SessionID)
	if err != nil {
		logger.Warn("invalid_session_id", slog.Any("error", err))
		return err
	}

	// 2. Fetch Session Aggregate
	session, err := uc.sessionRepo.FindByID(ctx, sid)
	if err != nil {
		logger.Error("session_lookup_failed", slog.Any("error", err))
		return err
	}
	if session == nil {
		logger.Warn("session_not_found")
		return domain.ErrSessionNotFound
	}

	// 3. Domain Logic
	now := uc.clock.Now()
	if err := session.Revoke(now); err != nil {
		logger.Warn("logout_rejected_by_aggregate",
			slog.String("session_id", sid.String()),
			slog.Any("error", err),
		)
		return err
	}

	// 4. Persistence
	if err := uc.sessionRepo.Save(ctx, session); err != nil {
		logger.Error("session_save_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, session.CollectEvents())

	logger.Info("logout_success", slog.String("session_id", sid.String()))

	return nil
}
