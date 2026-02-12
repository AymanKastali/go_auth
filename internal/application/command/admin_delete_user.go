package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IAdminDeleteUserHandler interface {
	Handle(ctx context.Context, id string) error
}

type adminDeleteUserHandler struct {
	userRepo    domain.IUserRepository
	sessionRepo domain.ISessionRepository
	clock       domain.IClock
	dispatcher  IEventDispatcher
}

func NewAdminDeleteUserHandler(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IAdminDeleteUserHandler {
	return &adminDeleteUserHandler{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		clock:       clock,
		dispatcher:  dispatcher,
	}
}

func (h *adminDeleteUserHandler) Handle(ctx context.Context, id string) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "AdminDeleteUser"))

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
	if err := user.MarkDeleted(now); err != nil {
		return err
	}

	if err := h.userRepo.Save(ctx, user); err != nil {
		logger.Error("user_save_failed", slog.Any("error", err))
		return err
	}

	if err := h.sessionRepo.RevokeAllForUser(ctx, userID, now); err != nil {
		logger.Error("session_revoke_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())
	logger.Info("user_deleted_by_admin", slog.String("user_id", id))
	return nil
}
