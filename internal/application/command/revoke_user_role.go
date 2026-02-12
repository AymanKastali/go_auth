package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IRevokeUserRoleHandler interface {
	Handle(ctx context.Context, cmd RevokeUserRoleCommand) error
}

type revokeUserRoleHandler struct {
	userRepo   domain.IUserRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewRevokeUserRoleHandler(
	userRepo domain.IUserRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IRevokeUserRoleHandler {
	return &revokeUserRoleHandler{
		userRepo:   userRepo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (h *revokeUserRoleHandler) Handle(ctx context.Context, cmd RevokeUserRoleCommand) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "RevokeUserRole"))

	userID, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		return err
	}

	roleName, err := domain.NewRoleName(cmd.RoleName)
	if err != nil {
		return err
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
	if err := user.RemoveRole(roleName, now); err != nil {
		return err
	}

	if err := h.userRepo.Save(ctx, user); err != nil {
		logger.Error("user_save_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())
	logger.Info("role_revoked_from_user",
		slog.String("user_id", cmd.UserID),
		slog.String("role", cmd.RoleName),
	)
	return nil
}
