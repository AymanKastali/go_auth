package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

type updateMeUseCase struct {
	userRepo   domain.IUserRepository
	clock      domain.IClock
	dispatcher IEventDispatcher
}

func NewUpdateMeUseCase(
	repo domain.IUserRepository,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IUpdateMeUseCase {
	return &updateMeUseCase{
		userRepo:   repo,
		clock:      clock,
		dispatcher: dispatcher,
	}
}

func (uc *updateMeUseCase) Execute(ctx context.Context, cmd UpdateMeCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "UpdateMe"))

	uid := GetUserID(ctx)
	if uid.IsEmpty() {
		logger.Warn("unauthorized_access")
		return ErrUnauthorized
	}

	emailVO, err := domain.NewEmail(cmd.Email)
	if err != nil {
		logger.Warn("invalid_email_format", slog.Any("error", err))
		return err
	}

	user, err := uc.userRepo.FindByID(ctx, uid)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}
	if user == nil {
		logger.Warn("user_not_found")
		return ErrResourceNotFound
	}

	if !user.Email().Equal(emailVO) {
		existing, err := uc.userRepo.FindByEmail(ctx, emailVO)
		if err != nil {
			logger.Error("email_check_failed", slog.Any("error", err))
			return err
		}
		if existing != nil {
			logger.Warn("email_already_taken", slog.String("new_email", cmd.Email))
			return domain.ErrUserEmailTaken
		}
	}

	if err := user.UpdateEmail(emailVO, uc.clock.Now()); err != nil {
		logger.Warn("update_email_denied", slog.Any("error", err))
		return err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, user.CollectEvents())

	logger.Info("update_me_success", slog.String("new_email", cmd.Email))

	return nil
}
