package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

type revokeUserRoleUseCase struct {
	userRepo   domain.IUserRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewRevokeUserRoleUseCase(
	userRepo domain.IUserRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IRevokeUserRoleUseCase {
	return &revokeUserRoleUseCase{
		userRepo:   userRepo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (uc *revokeUserRoleUseCase) Execute(ctx context.Context, cmd RevokeUserRoleCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "RevokeUserRole"))

	userID, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		return err
	}

	roleName, err := domain.NewRoleName(cmd.RoleName)
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
	if err := user.RemoveRole(roleName, now); err != nil {
		return err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("user_save_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, user.CollectEvents())
	logger.Info("role_revoked_from_user",
		slog.String("user_id", cmd.UserID),
		slog.String("role", cmd.RoleName),
	)
	return nil
}
