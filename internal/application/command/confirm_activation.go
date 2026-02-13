package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IConfirmActivationHandler interface {
	Handle(ctx context.Context, cmd ConfirmActivationCommand) error
}

type confirmActivationHandler struct {
	userRepo             domain.IUserRepository
	activationRepo       domain.IActivationTokenRepository
	tokenSvc             domain.ITokenService
	confirmActivation  domain.IConfirmActivation
	txManager            ITransactionManager
	clock                domain.IClock
	dispatcher           IEventDispatcher
}

func NewConfirmActivationHandler(
	userRepo domain.IUserRepository,
	activationRepo domain.IActivationTokenRepository,
	tokenSvc domain.ITokenService,
	confirmActivation domain.IConfirmActivation,
	txManager ITransactionManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) IConfirmActivationHandler {
	return &confirmActivationHandler{
		userRepo:            userRepo,
		activationRepo:      activationRepo,
		tokenSvc:            tokenSvc,
		confirmActivation: confirmActivation,
		txManager:           txManager,
		clock:               clock,
		dispatcher:          dispatcher,
	}
}

func (h *confirmActivationHandler) Handle(ctx context.Context, cmd ConfirmActivationCommand) error {
	logger := application.GetLogger(ctx).With(slog.String("handler", "ConfirmActivation"))

	if cmd.Token == "" {
		logger.Warn("invalid_activation_token")
		return domain.ErrTokenInvalid
	}

	hashedToken, err := h.tokenSvc.HashActivationToken(cmd.Token)
	if err != nil {
		logger.Error("token_hash_failed", slog.Any("error", err))
		return err
	}

	now := h.clock.Now()

	var user *domain.User
	var activation *domain.ActivationToken

	err = h.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		var err error
		activation, err = h.activationRepo.FindByHash(txCtx, hashedToken)
		if err != nil {
			return err
		}
		if activation == nil {
			return domain.ErrActivationTokenInvalid
		}

		user, err = h.userRepo.FindByID(txCtx, activation.UserID())
		if err != nil {
			return err
		}
		if user == nil {
			return domain.ErrUserNotFound
		}

		if err := h.confirmActivation.Confirm(user, activation, now); err != nil {
			return err
		}

		if err := h.userRepo.Save(txCtx, user); err != nil {
			return err
		}
		return h.activationRepo.Save(txCtx, activation)
	})
	if err != nil {
		logger.Warn("confirm_activation_failed", slog.Any("error", err))
		return err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())
	h.dispatcher.Dispatch(ctx, activation.CollectEvents())

	logger.Info("confirm_activation_success", slog.String("user_id", user.ID().String()))

	return nil
}
