package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

// Forget Password
type forgotPasswordUseCase struct {
	userRepository     domain.IUserRepository
	recoveryRepository domain.IRecoveryTokenRepository
	accountManager     domain.IUserAccountManager
	emailService       IEmailService
	transactionManager ITransactionManager
	clock              domain.IClock
	dispatcher         IEventDispatcher
}

func NewForgotPasswordUseCase(
	userRepository domain.IUserRepository,
	recoveryRepository domain.IRecoveryTokenRepository,
	accountManager domain.IUserAccountManager,
	emailService IEmailService,
	transactionManager ITransactionManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IForgotPasswordUseCase {
	return &forgotPasswordUseCase{
		userRepository:     userRepository,
		recoveryRepository: recoveryRepository,
		accountManager:     accountManager,
		emailService:       emailService,
		transactionManager: transactionManager,
		clock:              clock,
		dispatcher:         dispatcher,
	}
}

func (useCase *forgotPasswordUseCase) Execute(
	ctx context.Context,
	command ForgotPasswordCommand,
) error {
	logger := GetLogger(ctx).With(
		slog.String("email", command.Email),
		slog.String("use_case", "ForgotPassword"),
	)

	// 1. Value Object Conversion: Fail fast before entering the DB layer.
	email, err := domain.NewEmail(command.Email)
	if err != nil {
		logger.Warn("invalid_email_format", slog.Any("error", err))
		return err
	}

	// 2. Resolve Aggregate: Fetch the subject of the operation.
	user, err := useCase.userRepository.FindByEmail(ctx, email)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}

	// 3. Security Boundary: If user doesn't exist, we return nil.
	// This prevents account enumeration by treating "not found" as success.
	if user == nil {
		logger.Info("forgot_password_no_user")
		return nil
	}

	var rawToken domain.RawToken
	var token *domain.RecoveryToken

	// 4. Transactional Boundary: Managing persistence of Domain changes.
	err = useCase.transactionManager.WithTransaction(ctx, func(txCtx context.Context) error {
		raw, recoveryToken, err := useCase.accountManager.InitiatePasswordReset(
			user,
			useCase.clock.Now(),
		)
		if err != nil {
			return err
		}

		rawToken = raw
		token = recoveryToken

		return useCase.recoveryRepository.Save(txCtx, recoveryToken)
	})

	if err != nil {
		logger.Error("recovery_initiation_failed", slog.Any("error", err))
		return err
	}

	useCase.dispatcher.Dispatch(ctx, token.CollectEvents())

	// 5. Infrastructure side-effect: Send the RawToken to the user.
	if err := useCase.emailService.SendResetLink(user.Email().String(), rawToken.String()); err != nil {
		logger.Error("email_send_failed", slog.Any("error", err))
		return err
	}

	logger.Info("forgot_password_success")

	return nil
}
