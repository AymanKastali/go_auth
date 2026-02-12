package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IRevokePermissionHandler interface {
	Handle(ctx context.Context, cmd RevokePermissionCommand) error
}

type revokePermissionHandler struct {
	roleRepo   domain.IRoleRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewRevokePermissionHandler(
	roleRepo domain.IRoleRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IRevokePermissionHandler {
	return &revokePermissionHandler{
		roleRepo:   roleRepo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (h *revokePermissionHandler) Handle(ctx context.Context, cmd RevokePermissionCommand) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "RevokePermission"))

	roleID, err := domain.NewRoleID(cmd.RoleID)
	if err != nil {
		return err
	}

	perm, err := domain.NewPermission(cmd.Permission)
	if err != nil {
		return err
	}

	role, err := h.roleRepo.FindByID(ctx, roleID)
	if err != nil {
		logger.Error("role_lookup_failed", slog.Any("error", err))
		return err
	}
	if role == nil {
		return domain.ErrRoleNotFound
	}

	now := h.clock.Now()
	if err := role.RevokePermission(perm, now); err != nil {
		return err
	}

	if err := h.roleRepo.Save(ctx, role); err != nil {
		logger.Error("role_save_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, role.CollectEvents())
	return nil
}
