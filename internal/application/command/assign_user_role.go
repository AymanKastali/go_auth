package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IAssignUserRoleHandler interface {
	Handle(ctx context.Context, cmd AssignUserRoleCommand) error
}

type assignUserRoleHandler struct {
	userRepo   domain.IUserRepository
	roleRepo   domain.IRoleRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewAssignUserRoleHandler(
	userRepo domain.IUserRepository,
	roleRepo domain.IRoleRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IAssignUserRoleHandler {
	return &assignUserRoleHandler{
		userRepo:   userRepo,
		roleRepo:   roleRepo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (h *assignUserRoleHandler) Handle(ctx context.Context, cmd AssignUserRoleCommand) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "AssignUserRole"))

	userID, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		return err
	}

	roleName, err := domain.NewRoleName(cmd.RoleName)
	if err != nil {
		return err
	}

	role, err := h.roleRepo.FindByName(ctx, roleName)
	if err != nil {
		logger.Error("role_lookup_failed", slog.Any("error", err))
		return err
	}
	if role == nil {
		return domain.ErrRoleNotFound
	}

	user, err := h.userRepo.FindByID(ctx, userID)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	now := h.clock.Now()
	if err := user.AssignRole(roleName, now); err != nil {
		return err
	}

	if err := h.userRepo.Save(ctx, user); err != nil {
		logger.Error("user_save_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())
	logger.Info("role_assigned_to_user",
		slog.String("user_id", cmd.UserID),
		slog.String("role", cmd.RoleName),
	)
	return nil
}
