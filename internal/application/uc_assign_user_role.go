package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

type assignUserRoleUseCase struct {
	userRepo   domain.IUserRepository
	roleRepo   domain.IRoleRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewAssignUserRoleUseCase(
	userRepo domain.IUserRepository,
	roleRepo domain.IRoleRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IAssignUserRoleUseCase {
	return &assignUserRoleUseCase{
		userRepo:   userRepo,
		roleRepo:   roleRepo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (uc *assignUserRoleUseCase) Execute(ctx context.Context, cmd AssignUserRoleCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "AssignUserRole"))

	// 1. Parse and validate inputs
	userID, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		return err
	}

	roleName, err := domain.NewRoleName(cmd.RoleName)
	if err != nil {
		return err
	}

	// 2. Verify role exists
	role, err := uc.roleRepo.FindByName(ctx, roleName)
	if err != nil {
		logger.Error("role_lookup_failed", slog.Any("error", err))
		return err
	}
	if role == nil {
		return domain.ErrRoleNotFound
	}

	// 3. Load user
	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	// 4. Assign role
	now := uc.clock.Now()
	if err := user.AssignRole(roleName, now); err != nil {
		return err
	}

	// 5. Save
	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("user_save_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, user.CollectEvents())
	logger.Info("role_assigned_to_user",
		slog.String("user_id", cmd.UserID),
		slog.String("role", cmd.RoleName),
	)
	return nil
}
