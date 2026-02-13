package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type IRegisterHandler interface {
	Handle(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error)
}

type registerHandler struct {
	userRepo            domain.IUserRepository
	registrar           domain.IRegisterMember
	passwordPolicy      domain.IPasswordPolicy
	passwordSvc         domain.IPasswordService
	idGen               domain.IIDGenerator
	clock               domain.IClock
	dispatcher          IEventDispatcher
	initiateActivation domain.IInitiateActivation
	activationRepo      domain.IActivationTokenRepository
	emailSvc            IEmailService
	txManager           ITransactionManager
}

func NewRegisterHandler(
	userRepo domain.IUserRepository,
	registrar domain.IRegisterMember,
	passwordPolicy domain.IPasswordPolicy,
	passwordSvc domain.IPasswordService,
	idGen domain.IIDGenerator,
	clock domain.IClock,
	dispatcher IEventDispatcher,
	initiateActivation domain.IInitiateActivation,
	activationRepo domain.IActivationTokenRepository,
	emailSvc IEmailService,
	txManager ITransactionManager,
) IRegisterHandler {
	return &registerHandler{
		userRepo:            userRepo,
		registrar:           registrar,
		passwordPolicy:      passwordPolicy,
		passwordSvc:         passwordSvc,
		idGen:               idGen,
		clock:               clock,
		dispatcher:          dispatcher,
		initiateActivation: initiateActivation,
		activationRepo:      activationRepo,
		emailSvc:            emailSvc,
		txManager:           txManager,
	}
}

func (h *registerHandler) Handle(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error) {
	logger := application.GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("handler", "Register"),
	)

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	validatedPass, err := h.passwordPolicy.Validate(cmd.Password)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	uid, err := h.idGen.GenerateUserID()
	if err != nil {
		logger.Error("id_generation_failed", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	hashed, err := h.passwordSvc.Hash(validatedPass)
	if err != nil {
		logger.Error("password_hash_failed", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	now := h.clock.Now()

	user, err := h.registrar.Register(ctx, uid, email, hashed, now)
	if err != nil {
		logger.Warn("registration_domain_denied", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	var rawToken string
	var activationToken *domain.ActivationToken

	err = h.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		if err := h.userRepo.Save(txCtx, user); err != nil {
			return err
		}

		if !user.IsActive() && h.activationRepo != nil {
			raw, at, err := h.initiateActivation.Initiate(user, now)
			if err != nil {
				return err
			}
			rawToken = raw
			activationToken = at

			if err := h.activationRepo.Save(txCtx, at); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		logger.Error("registration_save_failed", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	h.dispatcher.Dispatch(ctx, user.CollectEvents())

	if activationToken != nil {
		h.dispatcher.Dispatch(ctx, activationToken.CollectEvents())

		if err := h.emailSvc.SendActivationLink(user.Email().String(), rawToken); err != nil {
			logger.Error("activation_email_send_failed", slog.Any("error", err))
			return ZeroRegisterUserResponse, err
		}
	}

	logger.Info("register_success", slog.String("user_id", user.ID().String()))

	return RegisterUserResponse{
		UserID: user.ID().String(),
		Email:  user.Email().String(),
	}, nil
}
