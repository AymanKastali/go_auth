package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

type logoutUseCase struct {
	userRepo   domain.IUserRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewLogoutUseCase(
	repo domain.IUserRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) ILogoutUseCase {
	return &logoutUseCase{
		userRepo:   repo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (uc *logoutUseCase) Execute(ctx context.Context, cmd LogoutCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "Logout"))

	// 1. VO Conversion (Fail Fast)
	uid, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		logger.Warn("invalid_user_id", slog.Any("error", err))
		return err
	}

	sid, err := domain.NewSessionID(cmd.SessionID)
	if err != nil {
		logger.Warn("invalid_session_id", slog.Any("error", err))
		return err
	}

	// 2. Identity Resolution
	user, err := uc.userRepo.FindByID(ctx, uid)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}
	if user == nil {
		logger.Warn("user_not_found")
		return domain.ErrUserNotFound
	}

	// 3. Domain Logic (Direct Aggregate Method)
	now := uc.clock.Now()
	if err := user.RevokeSession(sid, now); err != nil {
		logger.Warn("logout_rejected_by_aggregate",
			slog.String("session_id", sid.String()),
			slog.Any("error", err),
		)
		return err
	}

	// 4. Persistence
	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, user.CollectEvents())

	logger.Info("logout_success", slog.String("session_id", sid.String()))

	return nil
}
