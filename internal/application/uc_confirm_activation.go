package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

// Confirm Activation
type confirmActivationUseCase struct {
	userRepo       domain.IUserRepository
	activationRepo domain.IActivationTokenRepository
	tokenSvc       domain.ITokenService
	accountMgr     domain.IUserAccountManager
	txManager      ITransactionManager
	clock          domain.IClock
	dispatcher     IEventDispatcher
}

func NewConfirmActivationUseCase(
	userRepo domain.IUserRepository,
	activationRepo domain.IActivationTokenRepository,
	tokenSvc domain.ITokenService,
	accountMgr domain.IUserAccountManager,
	txManager ITransactionManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IConfirmActivationUseCase {
	return &confirmActivationUseCase{
		userRepo:       userRepo,
		activationRepo: activationRepo,
		tokenSvc:       tokenSvc,
		accountMgr:     accountMgr,
		txManager:      txManager,
		clock:          clock,
		dispatcher:     dispatcher,
	}
}

func (uc *confirmActivationUseCase) Execute(ctx context.Context, cmd ConfirmActivationCommand) error {
	logger := GetLogger(ctx).With(slog.String("use_case", "ConfirmActivation"))

	// 1. VO Conversion
	rawToken, err := domain.NewRawToken(cmd.Token)
	if err != nil {
		logger.Warn("invalid_activation_token", slog.Any("error", err))
		return err
	}

	// 2. Hash the token for lookup
	hashedToken, err := uc.tokenSvc.HashActivationToken(rawToken)
	if err != nil {
		logger.Error("token_hash_failed", slog.Any("error", err))
		return err
	}

	now := uc.clock.Now()

	var user *domain.User
	var activation *domain.ActivationToken

	// 3. Transaction Orchestration
	err = uc.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// 3a. Fetch activation token
		var err error
		activation, err = uc.activationRepo.FindByHash(txCtx, hashedToken)
		if err != nil {
			return err
		}
		if activation == nil {
			return domain.ErrActivationTokenInvalid
		}

		// 3b. Fetch user aggregate
		user, err = uc.userRepo.FindByID(txCtx, activation.UserID())
		if err != nil {
			return err
		}
		if user == nil {
			return domain.ErrUserNotFound
		}

		// 3c. Domain logic
		if err := uc.accountMgr.ConfirmActivation(user, activation, now); err != nil {
			return err
		}

		// 3d. Persist both aggregates
		if err := uc.userRepo.Save(txCtx, user); err != nil {
			return err
		}
		return uc.activationRepo.Save(txCtx, activation)
	})
	if err != nil {
		logger.Warn("confirm_activation_failed", slog.Any("error", err))
		return err
	}

	// 4. Dispatch events after commit
	uc.dispatcher.Dispatch(ctx, user.CollectEvents())
	uc.dispatcher.Dispatch(ctx, activation.CollectEvents())

	logger.Info("confirm_activation_success", slog.String("user_id", user.ID().String()))

	return nil
}
