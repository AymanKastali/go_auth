package application

import (
	"context"
	"go_auth/internal/core/domain"
)

// SeedingSuperAdmin
type seedSuperAdminUseCase struct {
	userRepo    domain.IUserRepository
	regService  domain.IRegisterUserService
	passwordSvc domain.IPasswordService
}

func NewSeedSuperAdminUseCase(
	repo domain.IUserRepository,
	svc domain.IRegisterUserService,
	pwd domain.IPasswordService,
) ISeedSuperAdmin {
	return &seedSuperAdminUseCase{
		userRepo:    repo,
		regService:  svc,
		passwordSvc: pwd,
	}
}

func (uc *seedSuperAdminUseCase) Execute(ctx context.Context, cmd RegisterUserCommand) error {
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return err
	}

	rawPassword, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		return err
	}

	user, err := uc.regService.Execute(ctx, email, rawPassword)
	if err != nil {
		return err
	}

	err = uc.userRepo.Save(ctx, user)
	if err != nil {
		return err
	}

	return nil
}

// Register Use Case
type registerUseCase struct {
	userRepo    domain.IUserRepository
	regService  domain.IRegisterUserService
	passwordSvc domain.IPasswordService
}

func NewRegisterUseCase(
	repo domain.IUserRepository,
	svc domain.IRegisterUserService,
	pwd domain.IPasswordService,
) IRegisterUseCase {
	return &registerUseCase{
		userRepo:    repo,
		regService:  svc,
		passwordSvc: pwd,
	}
}

func (uc *registerUseCase) Execute(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error) {
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	rawPassword, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	user, err := uc.regService.Execute(ctx, email, rawPassword)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	err = uc.userRepo.Save(ctx, user)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	return RegisterUserResponse{
		UserID: user.ID().String(),
		Email:  user.Email().String(),
	}, nil
}

// Login Use Case
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
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return ZeroLoginResponse, err
	}

	password, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		return ZeroLoginResponse, err
	}
	user, err := uc.authenticateUserSvc.Execute(
		ctx, email, password,
	)

	identity, err := domain.NewDeviceIdentity(
		cmd.IPAddress,
		cmd.OS,
		cmd.Browser,
		cmd.Model,
		cmd.AcceptLanguage,
		cmd.UserAgent,
		cmd.IsMobile,
	)
	if err != nil {
		return ZeroLoginResponse, err
	}

	session, rawToken, err := uc.establishUserSessionSvc.Execute(ctx, user, identity)

	accessToken, expiresAt, err := uc.accessGranter.GrantImmediateAccess(ctx, user, session.ID())
	if err != nil {
		return ZeroLoginResponse, err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		return ZeroLoginResponse, err
	}

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  expiresAt.String(),
		RefreshToken:       rawToken.String(),
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}

// Refresh Token Use Case
type refreshTokenUseCase struct {
	userRepo                  domain.IUserRepository
	refreshUserSessionService domain.IRefreshUserSession
	accessGranter             domain.IAccessGrantor
}

func NewRefreshTokenUseCase(
	repo domain.IUserRepository,
	refreshUserSessionService domain.IRefreshUserSession,
	accessGranter domain.IAccessGrantor,
) IRefreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepo:                  repo,
		refreshUserSessionService: refreshUserSessionService,
		accessGranter:             accessGranter,
	}
}

func (uc *refreshTokenUseCase) Execute(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error) {
	// 1. Map Primitives to Domain Value Objects (With proper error handling)
	uid, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		return ZeroLoginResponse, err
	}

	user, err := uc.userRepo.FindByID(ctx, uid)
	if err != nil {
		return ZeroLoginResponse, err
	}

	raw, err := domain.NewRawToken(cmd.RefreshToken)
	if err != nil {
		return ZeroLoginResponse, err
	}

	fp, err := domain.NewDeviceFingerprint(cmd.Fingerprint)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 2. Coordinate Domain Service
	// This now returns the session metadata needed for the response
	user, session, err := uc.refreshUserSessionService.Execute(ctx, user, raw, fp)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 3. Application Auth: Issue new stateless Access Token
	accessToken, expiresAt, err := uc.accessGranter.GrantImmediateAccess(ctx, user, session.ID())
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 4. Persist Aggregate changes (Heartbeat/Activity)
	if err := uc.userRepo.Save(ctx, user); err != nil {
		return ZeroLoginResponse, err
	}

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  expiresAt.String(),
		RefreshToken:       cmd.RefreshToken,
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}

// Validate Access (Query)
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
	token, err := domain.NewAccessToken(query.AccessToken)
	if err != nil {
		return ValidateAccessResponse{}, err
	}

	identity, err := uc.tokenService.Validate(token)
	if err != nil {
		return ValidateAccessResponse{}, err
	}

	user, err := uc.userRepo.FindByID(ctx, identity.UserID())
	if err != nil {
		return ValidateAccessResponse{}, err
	}

	now := uc.clock.Now()
	if err := user.ValidateIntegrity(identity.SessionID(), now); err != nil {
		return ValidateAccessResponse{}, err
	}

	return ValidateAccessResponse{
		UserID:    user.ID().String(),
		SessionID: identity.SessionID().String(),
		Roles:     user.RoleNames(),
	}, nil
}

// Logout Use Case
type logoutUseCase struct {
	userRepo domain.IUserRepository
	clock    domain.IClock
}

func NewLogoutUseCase(repo domain.IUserRepository, clock domain.IClock) ILogoutUseCase {
	return &logoutUseCase{userRepo: repo, clock: clock}
}

func (uc *logoutUseCase) Execute(ctx context.Context, cmd LogoutCommand) error {
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
		return err
	}

	// Aggregate logic: Remove/Revoke the session
	now := uc.clock.Now()
	if err := user.RevokeSession(sid, now); err != nil {
		return err
	}

	return MapToAppError(uc.userRepo.Save(ctx, user))
}
