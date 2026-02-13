package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IResetPasswordHandler interface {
	Handle(ctx context.Context, cmd ResetPasswordCommand) error
}

type resetPasswordHandler struct {
	userRepo         domain.IUserRepository
	sessionRepo      domain.ISessionRepository
	recoveryRepo     domain.IRecoveryTokenRepository
	tokenSvc         domain.ITokenService
	passwordPolicy   domain.IPasswordPolicy
	resetPassword domain.IResetPassword
	txManager        ITransactionManager
	clock            domain.IClock
	dispatcher       IEventDispatcher
}

func NewResetPasswordHandler(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	recoveryRepo domain.IRecoveryTokenRepository,
	tokenSvc domain.ITokenService,
	passwordPolicy domain.IPasswordPolicy,
	resetPassword domain.IResetPassword,
	txManager ITransactionManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IResetPasswordHandler {
	return &resetPasswordHandler{
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		recoveryRepo:     recoveryRepo,
		tokenSvc:         tokenSvc,
		passwordPolicy:   passwordPolicy,
		resetPassword: resetPassword,
		txManager:        txManager,
		clock:            clock,
		dispatcher:       dispatcher,
	}
}

func (h *resetPasswordHandler) Handle(ctx context.Context, cmd ResetPasswordCommand) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "ResetPassword"))

	if cmd.Token == "" {
		logger.Warn("invalid_reset_token")
		return domain.ErrTokenInvalid
	}

	validatedPass, err := h.passwordPolicy.Validate(cmd.NewPassword)
	if err != nil {
		logger.Warn("password_policy_violation", slog.Any("error", err))
		return err
	}

	hashedToken, err := h.tokenSvc.HashRecoveryToken(cmd.Token)
	if err != nil {
		logger.Error("token_hash_failed", slog.Any("error", err))
		return err
	}

	now := h.clock.Now()

	var user *domain.User
	var recovery *domain.RecoveryToken

	err = h.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		var err error
		recovery, err = h.recoveryRepo.FindByHash(txCtx, hashedToken)
		if err != nil {
			return err
		}
		if recovery == nil {
			return domain.ErrRecoveryTokenInvalid
		}

		user, err = h.userRepo.FindByID(txCtx, recovery.UserID())
		if err != nil {
			return err
		}
		if user == nil {
			return domain.ErrUserNotFound
		}

		if err := h.resetPassword.Reset(user, recovery, validatedPass, now); err != nil {
			return err
		}

		if err := h.userRepo.Save(txCtx, user); err != nil {
			return err
		}
		if err := h.recoveryRepo.Save(txCtx, recovery); err != nil {
			return err
		}

		return h.sessionRepo.RevokeAllForUser(txCtx, user.ID(), now)
	})
	if err != nil {
		logger.Warn("reset_password_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())
	h.dispatcher.Dispatch(ctx, recovery.CollectEvents())

	logger.Info("reset_password_success")

	return nil
}
