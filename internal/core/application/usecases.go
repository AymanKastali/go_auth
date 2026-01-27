package application

import (
	"context"
	"go_auth/internal/core/domain"
)

// SeedingSuperAdmin
type seedSuperAdminUseCase struct {
	userRepo    domain.IUserRepository
	regService  domain.IUserRegistrationService
	passwordSvc domain.IPasswordService
}

func NewSeedSuperAdminUseCase(
	repo domain.IUserRepository,
	svc domain.IUserRegistrationService,
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

	user, err := uc.regService.Register(ctx, email, rawPassword)
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
	regService  domain.IUserRegistrationService
	passwordSvc domain.IPasswordService
}

func NewRegisterUseCase(
	repo domain.IUserRepository,
	svc domain.IUserRegistrationService,
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

	user, err := uc.regService.Register(ctx, email, rawPassword)
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
	userRepo      domain.IUserRepository
	authSvc       domain.IAuthenticationService
	tokenProvider domain.IAccessTokenProvider
}

func NewLoginUseCase(
	repo domain.IUserRepository,
	svc domain.IAuthenticationService,
	provider domain.IAccessTokenProvider,
) ILoginUserUseCase {
	return &loginUseCase{
		userRepo:      repo,
		authSvc:       svc,
		tokenProvider: provider,
	}
}

func (uc *loginUseCase) Execute(ctx context.Context, cmd LoginCommand) (LoginResponse, error) {
	// 1. Transform Primitives -> Domain VOs
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return ZeroLoginResponse, err
	}

	password, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// Transform Device Primitives -> DeviceIdentity VO
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

	// 2. Call Domain Service with VOs
	user, session, rawRefreshToken, err := uc.authSvc.Authenticate(
		ctx, email, password, identity,
	)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 3. Issue stateless token
	accessToken, expiresAt, err := uc.tokenProvider.Generate(user, session.ID())
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 4. Persist
	if err := uc.userRepo.Save(ctx, user); err != nil {
		return ZeroLoginResponse, err
	}

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  expiresAt.String(),
		RefreshToken:       rawRefreshToken.String(),
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}

// Refresh Token Use Case
type refreshTokenUseCase struct {
	userRepo      domain.IUserRepository
	authSvc       domain.IAuthenticationService
	tokenProvider domain.IAccessTokenProvider
}

func NewRefreshTokenUseCase(
	repo domain.IUserRepository,
	svc domain.IAuthenticationService,
	provider domain.IAccessTokenProvider,
) IRefreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepo:      repo,
		authSvc:       svc,
		tokenProvider: provider,
	}
}

func (uc *refreshTokenUseCase) Execute(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error) {
	// 1. Map Primitives to Domain Value Objects (With proper error handling)
	uid, err := domain.NewUserID(cmd.UserID)
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
	user, session, err := uc.authSvc.RefreshUserSession(ctx, uid, raw, fp)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 3. Application Auth: Issue new stateless Access Token
	accessToken, expiresAt, err := uc.tokenProvider.Generate(user, session.ID())
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
	tokenProvider domain.IAccessTokenProvider
	userRepo      domain.IUserRepository
	identityGuard domain.IIdentityGuardService
}

func NewValidateAccessUseCase(
	provider domain.IAccessTokenProvider,
	repo domain.IUserRepository,
	identityGuard domain.IIdentityGuardService,

) IValidateAccessUseCase {
	return &validateAccessUseCase{
		tokenProvider: provider,
		userRepo:      repo,
		identityGuard: identityGuard,
	}
}

func (uc *validateAccessUseCase) Execute(ctx context.Context, query ValidateAccessQuery) (ValidateAccessResponse, error) {
	// 1. Reconstitute Technical Value Objects from Input
	token, err := domain.NewAccessToken(query.AccessToken)
	if err != nil {
		return ValidateAccessResponse{}, err
	}

	// 2. Technical Port: Cryptographic/Stateless Validation
	identity, err := uc.tokenProvider.Validate(token)
	if err != nil {
		return ValidateAccessResponse{}, err
	}

	// 3. Data Port: Retrieve the Aggregate Root
	user, err := uc.userRepo.FindByID(ctx, identity.UserID())
	if err != nil {
		return ValidateAccessResponse{}, err
	}

	// 4. Domain Service: Enforce Business Invariants
	// We pass 'now' into the Guard to handle temporal validation (expiration)
	if err := uc.identityGuard.CheckIntegrity(user, identity.SessionID()); err != nil {
		return ValidateAccessResponse{}, err
	}

	// 5. Success: Map to Response DTO
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
