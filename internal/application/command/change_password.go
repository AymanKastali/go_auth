package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IChangePasswordHandler interface {
	Handle(ctx context.Context, cmd ChangePasswordCommand) error
}

type changePasswordHandler struct {
	userRepo       domain.IUserRepository
	sessionRepo    domain.ISessionRepository
	accountManager domain.IUserAccountManager
	clock          domain.IClock
	dispatcher     IEventDispatcher
}

func NewChangePasswordHandler(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	accountManager domain.IUserAccountManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IChangePasswordHandler {
	return &changePasswordHandler{
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		accountManager: accountManager,
		clock:          clock,
		dispatcher:     dispatcher,
	}
}

func (h *changePasswordHandler) Handle(ctx context.Context, cmd ChangePasswordCommand) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "ChangePassword"))

	uid := application.GetUserID(ctx)
	if uid.IsEmpty() {
		logger.Warn("unauthorized_access")
		return application.ErrUnauthorized
	}

	user, err := h.userRepo.FindByID(ctx, uid)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return application.ErrResourceNotFound
	}
	if user == nil {
		logger.Warn("user_not_found")
		return application.ErrResourceNotFound
	}

	oldPass, err := domain.NewRawPassword(cmd.OldPassword)
	if err != nil {
		logger.Warn("invalid_old_password_format", slog.Any("error", err))
		return err
	}

	newPass, err := domain.NewRawPassword(cmd.NewPassword)
	if err != nil {
		logger.Warn("invalid_new_password_format", slog.Any("error", err))
		return err
	}

	now := h.clock.Now()
	if err := h.accountManager.ChangePassword(user, oldPass, newPass, now); err != nil {
		logger.Warn("change_password_denied", slog.Any("error", err))
		return err
	}

	if err := h.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return err
	}

	if err := h.sessionRepo.RevokeAllForUser(ctx, uid, now); err != nil {
		logger.Error("session_revoke_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())

	logger.Info("change_password_success")

	return nil
}
