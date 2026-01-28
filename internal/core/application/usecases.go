package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// --- Seed Super Admin Use Case ---

type seedSuperAdminUseCase struct {
	userRepo        domain.IUserRepository
	registerUserSvc domain.IRegisterUserService
}

func NewSeedSuperAdminUseCase(
	repo domain.IUserRepository,
	registerUserSvc domain.IRegisterUserService,
) ISeedSuperAdmin {
	return &seedSuperAdminUseCase{
		userRepo:        repo,
		registerUserSvc: registerUserSvc,
	}
}

func (uc *seedSuperAdminUseCase) Execute(ctx context.Context, cmd RegisterUserCommand) error {
	logger := GetLogger(ctx).With(slog.String("email", cmd.Email), slog.String("action", "seed_admin"))

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return err
	}

	rawPassword, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		return err
	}

	user, err := uc.registerUserSvc.Execute(ctx, email, rawPassword)
	if err != nil {
		logger.Error("seeding_registration_failed", slog.Any("error", err))
		return err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("seeding_persistence_failed", slog.Any("error", err))
		return err
	}

	logger.Info("super_admin_seeded_successfully")
	return nil
}

// --- Register Use Case ---

type registerUseCase struct {
	userRepo        domain.IUserRepository
	registerUserSvc domain.IRegisterUserService
}

func NewRegisterUseCase(
	userRepo domain.IUserRepository,
	registerUserSvc domain.IRegisterUserService,
) IRegisterUseCase {
	return &registerUseCase{
		userRepo:        userRepo,
		registerUserSvc: registerUserSvc,
	}
}

func (uc *registerUseCase) Execute(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error) {
	logger := GetLogger(ctx).With(slog.String("email", cmd.Email))

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	rawPassword, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	user, err := uc.registerUserSvc.Execute(ctx, email, rawPassword)
	if err != nil {
		logger.Warn("user_registration_aborted", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("user_registration_save_failed", slog.Any("error", err))
		return ZeroRegisterUserResponse, err
	}

	logger.Info("user_registration_completed", slog.String("user_id", user.ID().String()))
	return RegisterUserResponse{
		UserID: user.ID().String(),
		Email:  user.Email().String(),
	}, nil
}

// --- Login Use Case ---

type loginUseCase struct {
	userRepo                domain.IUserRepository
	authenticateUserSvc     domain.IAuthenticateUser
	establishUserSessionSvc domain.IEstablishUserSession
	accessGranter           domain.IAccessGrantor
}

func NewLoginUseCase(
	repo domain.IUserRepository,
	authenticateUserSvc domain.IAuthenticateUser,
	establishUserSessionSvc domain.IEstablishUserSession,
	accessGranter domain.IAccessGrantor,
) ILoginUserUseCase {
	return &loginUseCase{
		userRepo:                repo,
		authenticateUserSvc:     authenticateUserSvc,
		establishUserSessionSvc: establishUserSessionSvc,
		accessGranter:           accessGranter,
	}
}

func (uc *loginUseCase) Execute(ctx context.Context, cmd LoginCommand) (LoginResponse, error) {
	// GetLogger(ctx) provides the logger with the unified 'req_id' attached
	logger := GetLogger(ctx).With(slog.String("email", cmd.Email))

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return ZeroLoginResponse, err
	}

	password, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 1. Authenticate (Verify email/password)
	user, err := uc.authenticateUserSvc.Execute(ctx, email, password)
	if err != nil {
		logger.Warn("login_denied_invalid_credentials", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 2. Establish Session (Device Fingerprinting & Aggregate State Mutation)
	identity := GetIdentity(ctx)
	session, rawRefreshToken, err := uc.establishUserSessionSvc.Execute(ctx, user, identity)
	if err != nil {
		logger.Error("login_failed_session_establishment", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 3. Grant Access (JWT Generation)
	// FIX: Pass the actual session.ID() generated in step 2 to ensure the 'sid' claim is populated
	accessToken, expiresAt, err := uc.accessGranter.GrantImmediateAccess(ctx, user, session.ID())
	if err != nil {
		logger.Error("login_failed_token_generation", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 4. Persistence (Save User + Sessions in one transaction)
	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("login_failed_persistence", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	logger.Info("user_login_success",
		slog.String("user_id", user.ID().String()),
		slog.String("session_id", session.ID().String()),
	)

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  expiresAt.String(),
		RefreshToken:       rawRefreshToken.String(),
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}

// --- Refresh Token Use Case ---

type refreshTokenUseCase struct {
	userRepo                  domain.IUserRepository
	refreshUserSessionService domain.IRefreshSession
	accessGranter             domain.IAccessGrantor
}

func NewRefreshTokenUseCase(
	repo domain.IUserRepository,
	refreshUserSessionService domain.IRefreshSession,
	accessGranter domain.IAccessGrantor,
) IRefreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepo:                  repo,
		refreshUserSessionService: refreshUserSessionService,
		accessGranter:             accessGranter,
	}
}

func (uc *refreshTokenUseCase) Execute(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error) {
	logger := GetLogger(ctx).With(slog.String("use_case", "refresh_token"))

	// 1. Map Primitives to Domain VOs
	// Note: If NewRawToken fails, it likely returns an ErrRequiredAttribute or ErrInvalidAttribute
	raw, err := domain.NewRawToken(cmd.RefreshToken)
	if err != nil {
		logger.Warn("invalid_token_format", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	fp, err := domain.NewDeviceFingerprint(cmd.Fingerprint)
	if err != nil {
		logger.Warn("invalid_fingerprint_format", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 2. Execute Domain Service (Identity resolution happens here)
	user, session, err := uc.refreshUserSessionService.Execute(ctx, raw, fp)
	if err != nil {
		// We log it here because we have the context-aware logger
		logger.Warn("refresh_denied", slog.Any("error", err))
		return ZeroLoginResponse, err // err is already a DomainError (e.g., ErrInvalidToken)
	}

	// 3. Update Logger now that we know the UserID
	logger = logger.With(slog.String("user_id", user.ID().String()))

	// 4. Grant New Access
	accessToken, expiresAt, err := uc.accessGranter.GrantImmediateAccess(ctx, user, session.ID())
	if err != nil {
		// This is an internal logic or signing failure
		logger.Error("refresh_grant_failed", slog.Any("error", err))
		return ZeroLoginResponse, domain.NewInternalError("failed to generate access token", err)
	}

	// 5. Persist Aggregate changes
	if err := uc.userRepo.Save(ctx, user); err != nil {
		// Database failure is always a CodeInternal
		logger.Error("refresh_persistence_failed", slog.Any("error", err))
		return ZeroLoginResponse, err // userRepo.Save should already return ErrInternal
	}

	logger.Info("token_refresh_success", slog.String("session_id", session.ID().String()))

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  expiresAt.String(),
		RefreshToken:       cmd.RefreshToken,
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}

// --- Validate Access Use Case ---

type validateAccessUseCase struct {
	tokenService domain.IAccessTokenService
	userRepo     domain.IUserRepository
	clock        domain.IClock
}

func NewValidateAccessUseCase(
	provider domain.IAccessTokenService,
	repo domain.IUserRepository,
	clock domain.IClock,
) IValidateAccessUseCase {
	return &validateAccessUseCase{
		tokenService: provider,
		userRepo:     repo,
		clock:        clock,
	}
}

func (uc *validateAccessUseCase) Execute(ctx context.Context, query ValidateAccessQuery) (ValidateAccessResponse, error) {
	// 1. Fix the Logger label to be generic
	logger := GetLogger(ctx).With(slog.String("use_case", "ValidateAccess"))

	token, err := domain.NewAccessToken(query.AccessToken)
	if err != nil {
		return ZeroValidateAccessResponse, err
	}

	identity, err := uc.tokenService.Validate(token)
	if err != nil {
		logger.Debug("token_validation_failed", slog.Any("error", err))
		return ZeroValidateAccessResponse, err
	}

	// 2. Extract SID immediately for logging context
	sid := identity.SessionID()
	if sid.IsEmpty() {
		logger.Error("token_missing_session_id_claim")
		return ZeroValidateAccessResponse, domain.NewInvalidTokenError()
	}

	user, err := uc.userRepo.FindByID(ctx, identity.UserID())
	if err != nil || user == nil {
		logger.Warn("token_valid_but_user_missing", slog.String("user_id", identity.UserID().String()))
		return ZeroValidateAccessResponse, domain.NewUserNotFoundError(identity.UserID().String())
	}

	now := uc.clock.Now()

	// 3. Validate Integrity with the SID
	if err := user.ValidateIntegrity(sid, now); err != nil {
		logger.Warn("access_denied_integrity_violation",
			slog.String("user_id", user.ID().String()),
			slog.String("session_id", sid.String()), // Log SID explicitly here
			slog.Any("error", err),
		)
		return ZeroValidateAccessResponse, err
	}

	return ValidateAccessResponse{
		UserID:    user.ID().String(),
		SessionID: sid.String(),
		Roles:     user.RoleNames(),
	}, nil
} // --- Logout Use Case ---

type logoutUseCase struct {
	userRepo domain.IUserRepository
	clock    domain.IClock
}

func NewLogoutUseCase(repo domain.IUserRepository, clock domain.IClock) ILogoutUseCase {
	return &logoutUseCase{userRepo: repo, clock: clock}
}

func (uc *logoutUseCase) Execute(ctx context.Context, cmd LogoutCommand) error {
	logger := GetLogger(ctx)

	uid, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		return err
	}

	sid, err := domain.NewSessionID(cmd.SessionID)
	if err != nil {
		return err
	}

	user, err := uc.userRepo.FindByID(ctx, uid)
	if err != nil {
		logger.Warn("logout_attempt_on_invalid_user")
		return err
	}

	now := uc.clock.Now()
	if err := user.RevokeSession(sid, now); err != nil {
		logger.Warn("logout_failed_session_revocation", slog.Any("error", err))
		return err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		return err
	}

	logger.Info("user_logged_out")
	return nil
}
