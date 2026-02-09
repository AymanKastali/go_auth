package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

type adminActivateUserUseCase struct {
	userRepo   domain.IUserRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewAdminActivateUserUseCase(
	userRepo domain.IUserRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IAdminActivateUserUseCase {
	return &adminActivateUserUseCase{
		userRepo:   userRepo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (uc *adminActivateUserUseCase) Execute(ctx context.Context, id string) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "AdminActivateUser"))

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
	if err := user.Activate(now); err != nil {
		return err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("user_save_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, user.CollectEvents())
	logger.Info("user_activated_by_admin", slog.String("user_id", id))
	return nil
}
