package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// Reset Password
type resetPasswordUseCase struct {
	accountMgr domain.IUserAccountManager
	txManager  ITransactionManager
	clock      domain.IClock
}

func NewResetPasswordUseCase(
	accountMgr domain.IUserAccountManager,
	txManager ITransactionManager,
	clock domain.IClock,
) IResetPasswordUseCase {
	return &resetPasswordUseCase{
		accountMgr: accountMgr,
		txManager:  txManager,
		clock:      clock,
	}
}

func (uc *resetPasswordUseCase) Execute(ctx context.Context, cmd ResetPasswordCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "ResetPassword"))

	// 1. VO Conversion
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

	// 2. Transaction Orchestration
	err = uc.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		return uc.accountMgr.ResetPasswordByToken(
			txCtx,
			rawToken,
			rawPassword,
			uc.clock.Now(),
		)
	})
	if err != nil {
		logger.Warn("reset_password_failed", slog.Any("error", err))
		return err
	}

	logger.Info("reset_password_success")

	return nil
}
