package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// Reset Password
type resetPasswordUseCase struct {
	userRepo     domain.IUserRepository
	sessionRepo  domain.ISessionRepository
	recoveryRepo domain.IRecoveryTokenRepository
	tokenSvc     domain.ITokenService
	accountMgr   domain.IUserAccountManager
	txManager    ITransactionManager
	clock        domain.IClock
	dispatcher   IEventDispatcher
}

func NewResetPasswordUseCase(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	recoveryRepo domain.IRecoveryTokenRepository,
	tokenSvc domain.ITokenService,
	accountMgr domain.IUserAccountManager,
	txManager ITransactionManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IResetPasswordUseCase {
	return &resetPasswordUseCase{
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

	// 2. Hash the token for lookup
	hashedToken, err := uc.tokenSvc.HashRecoveryToken(rawToken)
	if err != nil {
		logger.Error("token_hash_failed", slog.Any("error", err))
		return err
	}

	now := uc.clock.Now()

	var user *domain.User
	var recovery *domain.RecoveryToken

	// 3. Transaction Orchestration
	err = uc.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// 3a. Fetch recovery token
		var err error
		recovery, err = uc.recoveryRepo.FindByHash(txCtx, hashedToken)
		if err != nil {
			return err
		}
		if recovery == nil {
			return domain.ErrRecoveryTokenInvalid
		}

		// 3b. Fetch user aggregate
		user, err = uc.userRepo.FindByID(txCtx, recovery.UserID())
		if err != nil {
			return err
		}
		if user == nil {
			return domain.ErrUserNotFound
		}

		// 3c. Domain logic
		if err := uc.accountMgr.ResetPasswordByToken(user, recovery, rawPassword, now); err != nil {
			return err
		}

		// 3d. Persist both aggregates
		if err := uc.userRepo.Save(txCtx, user); err != nil {
			return err
		}
		if err := uc.recoveryRepo.Save(txCtx, recovery); err != nil {
			return err
		}

		// 3e. Revoke all sessions for security
		return uc.sessionRepo.RevokeAllForUser(txCtx, user.ID(), now)
	})
	if err != nil {
		logger.Warn("reset_password_failed", slog.Any("error", err))
		return err
	}

	// 4. Dispatch events after commit
	uc.dispatcher.Dispatch(ctx, user.CollectEvents())
	uc.dispatcher.Dispatch(ctx, recovery.CollectEvents())

	logger.Info("reset_password_success")

	return nil
}
