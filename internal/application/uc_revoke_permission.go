package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

type revokePermissionUseCase struct {
	roleRepo   domain.IRoleRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewRevokePermissionUseCase(
	roleRepo domain.IRoleRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IRevokePermissionUseCase {
	return &revokePermissionUseCase{
		roleRepo:   roleRepo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (uc *revokePermissionUseCase) Execute(ctx context.Context, cmd RevokePermissionCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "RevokePermission"))

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
	if err := role.RevokePermission(perm, now); err != nil {
		return err
	}

	if err := uc.roleRepo.Save(ctx, role); err != nil {
		logger.Error("role_save_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, role.CollectEvents())
	return nil
}
