package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IAdminActivateUserHandler interface {
	Handle(ctx context.Context, id string) error
}

type adminActivateUserHandler struct {
	userRepo   domain.IUserRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewAdminActivateUserHandler(
	userRepo domain.IUserRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IAdminActivateUserHandler {
	return &adminActivateUserHandler{
		userRepo:   userRepo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (h *adminActivateUserHandler) Handle(ctx context.Context, id string) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "AdminActivateUser"))

	userID, err := domain.NewUserID(id)
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
	if err := user.Activate(now); err != nil {
		return err
	}

	if err := h.userRepo.Save(ctx, user); err != nil {
		logger.Error("user_save_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())
	logger.Info("user_activated_by_admin", slog.String("user_id", id))
	return nil
}
