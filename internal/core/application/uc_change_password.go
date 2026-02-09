package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

type changePasswordUseCase struct {
	userRepo       domain.IUserRepository
	sessionRepo    domain.ISessionRepository
	accountManager domain.IUserAccountManager
	clock          domain.IClock
	dispatcher     IEventDispatcher
}

func NewChangePasswordUseCase(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	accountManager domain.IUserAccountManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IChangePasswordUseCase {
	return &changePasswordUseCase{
		userRepo:       userRepo,
		sessionRepo:    sessionRepo,
		accountManager: accountManager,
		clock:          clock,
		dispatcher:     dispatcher,
	}
}

func (uc *changePasswordUseCase) Execute(ctx context.Context, cmd ChangePasswordCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "ChangePassword"))

	// 1. Resolve Identity
	uid := GetUserID(ctx)
	if uid.IsEmpty() {
		logger.Warn("unauthorized_access")
		return ErrUnauthorized
	}

	// 2. Fetch Aggregate
	user, err := uc.userRepo.FindByID(ctx, uid)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return ErrResourceNotFound
	}
	if user == nil {
		logger.Warn("user_not_found")
		return ErrResourceNotFound
	}

	// 3. Value Object Conversion
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

	// 4. Delegate to Domain Manager
	now := uc.clock.Now()
	if err := uc.accountManager.ChangePassword(user, oldPass, newPass, now); err != nil {
		logger.Warn("change_password_denied", slog.Any("error", err))
		return err
	}

	// 5. Persistence
	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return err
	}

	// 6. Revoke all sessions for security
	if err := uc.sessionRepo.RevokeAllForUser(ctx, uid, now); err != nil {
		logger.Error("session_revoke_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, user.CollectEvents())

	logger.Info("change_password_success")

	return nil
}
