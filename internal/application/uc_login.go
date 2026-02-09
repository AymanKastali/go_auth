package application

import (
	"context"
	"go_auth/internal/domain"
	"log/slog"
)

// --- Login Use Case ---
type loginUseCase struct {
	userRepo      domain.IUserRepository
	sessionRepo   domain.ISessionRepository
	authSvc       domain.IAuthenticationService
	accessManager domain.IAccessManager
	clock         domain.IClock
	dispatcher    IEventDispatcher
}

func NewLoginUseCase(
	userRepo domain.IUserRepository,
	sessionRepo domain.ISessionRepository,
	authSvc domain.IAuthenticationService,
	accessManager domain.IAccessManager,
	clock domain.IClock,
	dispatcher IEventDispatcher,
) ILoginUseCase {
	return &loginUseCase{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		authSvc:       authSvc,
		accessManager: accessManager,
		clock:         clock,
		dispatcher:    dispatcher,
	}
}

func (uc *loginUseCase) Execute(ctx context.Context, cmd LoginCommand) (LoginResponse, error) {
	logger := GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("use_case", "Login"),
	)

	// 1. VO Conversion
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

	// 2. Fetch Aggregate
	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		logger.Error("user_lookup_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}
	if user == nil {
		logger.Warn("user_not_found")
		return ZeroLoginResponse, domain.ErrAuthenticationFailed
	}

	// 3. Authenticate and Establish Session (Domain Service)
	now := uc.clock.Now()
	rawRefreshToken, session, err := uc.authSvc.AuthenticateAndEstablishSession(
		ctx, user, rawPassword, GetIdentity(ctx), now,
	)
	if err != nil {
		logger.Warn("auth_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 4. Grant Access (Domain Service)
	accessToken, accessExpiry, err := uc.accessManager.GrantImmediateAccess(ctx, user, session.ID(), now)
	if err != nil {
		logger.Error("access_grant_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 5. Persistence
	if err := uc.sessionRepo.Save(ctx, session); err != nil {
		logger.Error("session_save_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	uc.dispatcher.Dispatch(ctx, session.CollectEvents())

	logger.Info("login_success", slog.String("user_id", user.ID().String()))

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  accessExpiry.String(),
		RefreshToken:       rawRefreshToken.String(),
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}
