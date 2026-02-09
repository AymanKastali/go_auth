package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

type assignPermissionUseCase struct {
	roleRepo   domain.IRoleRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewAssignPermissionUseCase(
	roleRepo domain.IRoleRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IAssignPermissionUseCase {
	return &assignPermissionUseCase{
		roleRepo:   roleRepo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (uc *assignPermissionUseCase) Execute(ctx context.Context, cmd AssignPermissionCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "AssignPermission"))

	roleID, err := domain.NewRoleID(cmd.RoleID)
	if err != nil {
		return err
	}

	perm, err := domain.NewPermission(cmd.Permission)
	if err != nil {
		return err
	}

	role, err := uc.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		logger.Error("role_lookup_failed", slog.Any("error", err))
		return err
	}
	if role == nil {
		return domain.ErrRoleNotFound
	}

	now := uc.clock.Now()
	role.AssignPermission(perm, now)

	if err := uc.roleRepo.Save(ctx, role); err != nil {
		logger.Error("role_save_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, role.CollectEvents())
	return nil
}
