package command

import (
	"context"
	"log/slog"

	"go_auth/internal/application"
	"go_auth/internal/domain"
)

type ILoginHandler interface {
	Handle(ctx context.Context, cmd LoginCommand) (LoginResponse, error)
}

type loginHandler struct {
	userRepo    domain.IUserRepository
	sessionRepo domain.ISessionRepository
	verifier    domain.IVerifyCredentials
	opener      domain.IOpenSession
	granter     domain.IGrantAccess
	clock       domain.IClock
	dispatcher  IEventDispatcher
	txManager   ITransactionManager
	loginPolicy domain.ILoginPolicy
}

func NewLoginHandler(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	verifier domain.IVerifyCredentials,
	opener domain.IOpenSession,
	granter domain.IGrantAccess,
	clock domain.IClock,
	dispatcher IEventDispatcher,
	txManager ITransactionManager,
	loginPolicy domain.ILoginPolicy,
) ILoginHandler {
	return &loginHandler{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		verifier:    verifier,
		opener:      opener,
		granter:     granter,
		clock:       clock,
		dispatcher:  dispatcher,
		txManager:   txManager,
		loginPolicy: loginPolicy,
	}
}

func (h *loginHandler) Handle(ctx context.Context, cmd LoginCommand) (LoginResponse, error) {
	logger := application.GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("handler", "Login"),
	)

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return ZeroLoginResponse, err
	}

	user, err := h.userRepo.FindByEmail(ctx, email)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}
	if user == nil {
		return ZeroLoginResponse, domain.ErrAuthenticationFailed
	}

	now := h.clock.Now()

	if user.IsLocked(now) {
		logger.Warn("account_locked", slog.String("user_id", user.ID().String()))
		return ZeroLoginResponse, domain.ErrAccountLocked
	}

	if err := h.verifier.Verify(user, cmd.Password); err != nil {
		user.RecordFailedLogin(
			h.loginPolicy.GetMaxAttempts(),
			h.loginPolicy.GetLockoutDuration(),
			now,
		)
		if saveErr := h.userRepo.Save(ctx, user); saveErr != nil {
			logger.Error("failed_login_save_failed", slog.Any("error", saveErr))
		}
		h.dispatcher.Dispatch(ctx, user.CollectEvents())
		logger.Warn("auth_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	hadFailedAttempts := user.FailedLoginAttempts() > 0
	if hadFailedAttempts {
		user.ResetLoginAttempts()
	}

	rawRefreshToken, session, revokedSession, err := h.opener.Open(
		ctx, user.ID(), application.GetIdentity(ctx), now,
	)
	if err != nil {
		logger.Error("session_establish_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	accessToken, accessExpiry, err := h.granter.Grant(ctx, user, session.ID(), now)
	if err != nil {
		logger.Error("access_grant_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	err = h.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		if revokedSession != nil {
			if err := h.sessionRepo.Save(txCtx, revokedSession); err != nil {
				return err
			}
		}
		if err := h.sessionRepo.Save(txCtx, session); err != nil {
			return err
		}
		if hadFailedAttempts {
			return h.userRepo.Save(txCtx, user)
		}
		return nil
	})
	if err != nil {
		logger.Error("session_save_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	if revokedSession != nil {
		h.dispatcher.Dispatch(ctx, revokedSession.CollectEvents())
	}
	h.dispatcher.Dispatch(ctx, session.CollectEvents())

	logger.Info("login_success", slog.String("user_id", user.ID().String()))

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  accessExpiry.String(),
		RefreshToken:       rawRefreshToken,
		RefreshTokenExpiry: session.Expiry().Time().String(),
	}, nil
}
