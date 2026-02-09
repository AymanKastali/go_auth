package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

// Resend Activation
type resendActivationUseCase struct {
	userRepo       domain.IUserRepository
	activationRepo domain.IActivationTokenRepository
	accountManager domain.IUserAccountManager
	emailSvc       IEmailService
	txManager      ITransactionManager
	clock          domain.IClock
	dispatcher     IEventDispatcher
}

func NewResendActivationUseCase(
	userRepo domain.IUserRepository,
	activationRepo domain.IActivationTokenRepository,
	accountManager domain.IUserAccountManager,
	emailSvc IEmailService,
	txManager ITransactionManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IResendActivationUseCase {
	return &resendActivationUseCase{
		userRepo:       userRepo,
		activationRepo: activationRepo,
		accountManager: accountManager,
		emailSvc:       emailSvc,
		txManager:      txManager,
		clock:          clock,
		dispatcher:     dispatcher,
	}
}

func (uc *resendActivationUseCase) Execute(ctx context.Context, cmd ResendActivationCommand) error {
	logger := GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("use_case", "ResendActivation"),
	)

	// 1. VO Conversion
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		logger.Warn("invalid_email_format", slog.Any("error", err))
		return err
	}

	// 2. Resolve Aggregate
	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}

	// 3. Security Boundary: Don't reveal if user exists
	if user == nil {
		logger.Info("resend_activation_no_user")
		return nil
	}

	// 4. If already active, return error
	if user.IsActive() {
		return domain.ErrUserAlreadyActive
	}

	now := uc.clock.Now()

	var rawToken domain.RawToken
	var token *domain.ActivationToken

	// 5. Transactional Boundary
	err = uc.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// 5a. Revoke all existing activation tokens
		if err := uc.activationRepo.RevokeAllForUser(txCtx, user.ID(), now); err != nil {
			return err
		}

		// 5b. Initiate new activation
		raw, activationToken, err := uc.accountManager.InitiateActivation(user, now)
		if err != nil {
			return err
		}

		rawToken = raw
		token = activationToken

		return uc.activationRepo.Save(txCtx, activationToken)
	})

	if err != nil {
		logger.Error("resend_activation_failed", slog.Any("error", err))
		return err
	}

	uc.dispatcher.Dispatch(ctx, token.CollectEvents())

	// 6. Send activation email
	if err := uc.emailSvc.SendActivationLink(user.Email().String(), rawToken.String()); err != nil {
		logger.Error("activation_email_send_failed", slog.Any("error", err))
		return err
	}

	logger.Info("resend_activation_success")

	return nil
}
