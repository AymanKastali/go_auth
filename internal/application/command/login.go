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
	userRepo      domain.IUserRepository
	sessionRepo   domain.ISessionRepository
	authSvc       domain.IAuthenticationService
	accessManager domain.IAccessManager
	clock         domain.IClock
	dispatcher    IEventDispatcher
}

func NewLoginHandler(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	authSvc domain.IAuthenticationService,
	accessManager domain.IAccessManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) ILoginHandler {
	return &loginHandler{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		authSvc:       authSvc,
		accessManager: accessManager,
		clock:         clock,
		dispatcher:    dispatcher,
	}
}

func (h *loginHandler) Handle(ctx context.Context, cmd LoginCommand) (LoginResponse, error) {
	logger := application.GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("handler", "Login"),
	)

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		logger.Warn("invalid_email_format", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	rawPassword, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		logger.Warn("invalid_password_format", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	user, err := h.userRepo.FindByEmail(ctx, email)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}
	if user == nil {
		logger.Warn("user_not_found")
		return ZeroLoginResponse, domain.ErrAuthenticationFailed
	}

	now := h.clock.Now()
	rawRefreshToken, session, err := h.authSvc.AuthenticateAndEstablishSession(
		ctx, user, rawPassword, application.GetIdentity(ctx), now,
	)
	if err != nil {
		logger.Warn("auth_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	accessToken, accessExpiry, err := h.accessManager.GrantImmediateAccess(ctx, user, session.ID(), now)
	if err != nil {
		logger.Error("access_grant_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	if err := h.sessionRepo.Save(ctx, session); err != nil {
		logger.Error("session_save_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	h.dispatcher.Dispatch(ctx, session.CollectEvents())

	logger.Info("login_success", slog.String("user_id", user.ID().String()))

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  accessExpiry.String(),
		RefreshToken:       rawRefreshToken.String(),
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}
