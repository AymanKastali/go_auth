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
	userRepo     domain.IUserRepository
	sessionRepo  domain.ISessionRepository
	recoveryRepo domain.IRecoveryTokenRepository
	tokenSvc     domain.ITokenService
	accountMgr   domain.IUserAccountManager
	txManager    ITransactionManager
	clock        domain.IClock
	dispatcher   IEventDispatcher
}

func NewResetPasswordHandler(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	recoveryRepo domain.IRecoveryTokenRepository,
	tokenSvc domain.ITokenService,
	accountMgr domain.IUserAccountManager,
	txManager ITransactionManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IResetPasswordHandler {
	return &resetPasswordHandler{
		userRepo:     userRepo,
		sessionRepo:  sessionRepo,
		recoveryRepo: recoveryRepo,
		tokenSvc:     tokenSvc,
		accountMgr:   accountMgr,
		txManager:    txManager,
		clock:        clock,
		dispatcher:   dispatcher,
	}
}

func (h *resetPasswordHandler) Handle(ctx context.Context, cmd ResetPasswordCommand) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "ResetPassword"))

	rawToken, err := domain.NewRawToken(cmd.Token)
	if err != nil {
		logger.Warn("invalid_reset_token", slog.Any("error", err))
		return err
	}

	rawPassword, err := domain.NewRawPassword(cmd.NewPassword)
	if err != nil {
		logger.Warn("invalid_password_format", slog.Any("error", err))
		return err
	}

	hashedToken, err := h.tokenSvc.HashRecoveryToken(rawToken)
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

		if err := h.accountMgr.ResetPasswordByToken(user, recovery, rawPassword, now); err != nil {
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
