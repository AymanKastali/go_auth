package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IUpdateMeHandler interface {
	Handle(ctx context.Context, cmd UpdateMeCommand) error
}

type updateMeHandler struct {
	userRepo   domain.IUserRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewUpdateMeHandler(
	repo domain.IUserRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IUpdateMeHandler {
	return &updateMeHandler{
		userRepo:   repo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (h *updateMeHandler) Handle(ctx context.Context, cmd UpdateMeCommand) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "UpdateMe"))

	uid := application.GetUserID(ctx)
	if uid.IsEmpty() {
		return application.ErrUnauthorized
	}

	emailVO, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return err
	}

	user, err := h.userRepo.FindByID(ctx, uid)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}
	if user == nil {
		return application.ErrResourceNotFound
	}

	if !user.Email().Equal(emailVO) {
		existing, err := h.userRepo.FindByEmail(ctx, emailVO)
		if err != nil {
			logger.Error("email_check_failed", slog.Any("error", err))
			return err
		}
		if existing != nil {
			return domain.ErrUserEmailTaken
		}
	}

	if err := user.UpdateEmail(emailVO, h.clock.Now()); err != nil {
		return err
	}

	if err := h.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())

	logger.Info("update_me_success", slog.String("new_email", cmd.Email))

	return nil
}
