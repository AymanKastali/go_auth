package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IForgotPasswordHandler interface {
	Handle(ctx context.Context, cmd ForgotPasswordCommand) error
}

type forgotPasswordHandler struct {
	userRepository     domain.IUserRepository
	recoveryRepository domain.IRecoveryTokenRepository
	initiateRecovery  domain.IInitiateRecovery
	emailService       IEmailService
	transactionManager ITransactionManager
	clock              domain.IClock
	dispatcher         IEventDispatcher
}

func NewForgotPasswordHandler(
	userRepository domain.IUserRepository,
	recoveryRepository domain.IRecoveryTokenRepository,
	initiateRecovery domain.IInitiateRecovery,
	emailService IEmailService,
	transactionManager ITransactionManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IForgotPasswordHandler {
	return &forgotPasswordHandler{
		userRepository:     userRepository,
		recoveryRepository: recoveryRepository,
		initiateRecovery:  initiateRecovery,
		emailService:       emailService,
		transactionManager: transactionManager,
		clock:              clock,
		dispatcher:         dispatcher,
	}
}

func (h *forgotPasswordHandler) Handle(ctx context.Context, cmd ForgotPasswordCommand) error {
	logger := application.GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("handler", "ForgotPassword"),
	)

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return err
	}

	user, err := h.userRepository.FindByEmail(ctx, email)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return err
	}

	if user == nil {
		return nil
	}

	var rawToken string
	var token *domain.RecoveryToken

	err = h.transactionManager.WithTransaction(ctx, func(txCtx context.Context) error {
		raw, recoveryToken, err := h.initiateRecovery.Initiate(
			user,
			h.clock.Now(),
		)
		if err != nil {
			return err
		}

		rawToken = raw
		token = recoveryToken

		return h.recoveryRepository.Save(txCtx, recoveryToken)
	})

	if err != nil {
		logger.Error("recovery_initiation_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, token.CollectEvents())

	if err := h.emailService.SendResetLink(user.Email().String(), rawToken); err != nil {
		logger.Error("email_send_failed", slog.Any("error", err))
		return err
	}

	logger.Info("forgot_password_success")

	return nil
}
