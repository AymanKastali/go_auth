package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

type adminDeleteUserUseCase struct {
	userRepo    domain.IUserRepository
	sessionRepo domain.ISessionRepository
	clock       domain.IClock
	dispatcher  IEventDispatcher
}

func NewAdminDeleteUserUseCase(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IAdminDeleteUserUseCase {
	return &adminDeleteUserUseCase{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		clock:       clock,
		dispatcher:  dispatcher,
	}
}

func (uc *adminDeleteUserUseCase) Execute(ctx context.Context, id string) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "AdminDeleteUser"))

	userID, err := domain.NewUserID(id)
	if err != nil {
		return err
	}

	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	now := uc.clock.Now()
	if err := user.MarkDeleted(now); err != nil {
		return err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("user_save_failed", slog.Any("error", err))
		return err
	}

	// Revoke all active sessions
	if err := uc.sessionRepo.RevokeAllForUser(ctx, userID, now); err != nil {
		logger.Error("session_revoke_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, user.CollectEvents())
	logger.Info("user_deleted_by_admin", slog.String("user_id", id))
	return nil
}
