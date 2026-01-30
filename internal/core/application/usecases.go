package application

import (
	"context"
	"go_auth/internal/core/domain"
	"log/slog"
)

// --- Seed Super Admin Use Case ---
type seedSuperAdminUseCase struct {
	userRepo        domain.IUserRepository
	registrationSvc domain.IRegistrationService
	passwordMgr     domain.IPasswordManager
	idGen           domain.IIDGenerator
	clock           domain.IClock
}

func NewSeedSuperAdminUseCase(
	userRepo domain.IUserRepository,
	registrationSvc domain.IRegistrationService,
	passwordMgr domain.IPasswordManager,
	idGen domain.IIDGenerator,
	clock domain.IClock,
) ISeedSuperAdminUseCase {
	return &seedSuperAdminUseCase{
		userRepo:        userRepo,
		registrationSvc: registrationSvc,
		passwordMgr:     passwordMgr,
		idGen:           idGen,
		clock:           clock,
	}
}

func (uc *seedSuperAdminUseCase) Execute(ctx context.Context, cmd RegisterUserCommand) error {
	logger := GetLogger(ctx).With(
		slog.String("email", cmd.Email),
		slog.String("use_case", "SeedSuperAdmin"),
	)

	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		logger.Warn("invalid_email_format", slog.Any("error", err))
		return err
	}

	rawPassword, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		logger.Warn("invalid_password_format", slog.Any("error", err))
		return err
	}

	hashedPassword, err := uc.passwordMgr.ValidateAndHashNewPassword(rawPassword)
	if err != nil {
		logger.Warn("password_policy_violation", slog.Any("error", err))
		return err
	}

	uidVO, err := uc.idGen.GenerateUserID()
	if err != nil {
		logger.Error("id_generation_failed", slog.Any("error", err))
		return err
	}

	now := uc.clock.Now()

	user, err := uc.registrationSvc.RegisterNewSuperAdmin(ctx, uidVO, email, hashedPassword, now)
	if err != nil {
		logger.Warn("registration_domain_denied", slog.Any("error", err))
		return err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		logger.Error("database_save_failed", slog.Any("error", err))
		return err
	}

	logger.Info("super_admin_seeded_successfully",
		slog.String("user_id", user.ID().String()),
	)

	return nil
}

// --- Register Use Case ---
type registerUseCase struct {
	userRepo        domain.IUserRepository
	registrationSvc domain.IRegistrationService
	passwordMgr     domain.IPasswordManager
	idGen           domain.IIDGenerator
	clock           domain.IClock
}

func NewRegisterUseCase(
	userRepo domain.IUserRepository,
	registrationSvc domain.IRegistrationService,
	passwordMgr domain.IPasswordManager,
	idGen domain.IIDGenerator,
	clock domain.IClock,
) IRegisterUseCase {
	return &registerUseCase{
		userRepo:        userRepo,
		registrationSvc: registrationSvc,
		passwordMgr:     passwordMgr,
		idGen:           idGen,
		clock:           clock,
	}
}

func (uc *registerUseCase) Execute(ctx context.Context, cmd RegisterUserCommand) (RegisterUserResponse, error) {
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	rawPass, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	uid, err := uc.idGen.GenerateUserID()
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	hashed, err := uc.passwordMgr.ValidateAndHashNewPassword(rawPass)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	now := uc.clock.Now()

	user, err := uc.registrationSvc.RegisterNewMember(ctx, uid, email, hashed, now)
	if err != nil {
		return ZeroRegisterUserResponse, err
	}

	if err := uc.userRepo.Save(ctx, user); err != nil {
		return ZeroRegisterUserResponse, err
	}

	return RegisterUserResponse{
		UserID: user.ID().String(),
		Email:  user.Email().String(),
	}, nil
}

// --- Login Use Case ---
type loginUseCase struct {
	userRepo      domain.IUserRepository
	authSvc       domain.IAuthenticationService
	accessManager domain.IAccessManager
	clock         domain.IClock
}

func NewLoginUseCase(
	userRepo domain.IUserRepository,
	authSvc domain.IAuthenticationService,
	accessManager domain.IAccessManager,
	clock domain.IClock,
) ILoginUseCase {
	return &loginUseCase{
		userRepo:      userRepo,
		authSvc:       authSvc,
		accessManager: accessManager,
		clock:         clock,
	}
}

func (uc *loginUseCase) Execute(ctx context.Context, cmd LoginCommand) (LoginResponse, error) {
	logger := GetLogger(ctx).With(slog.String("email", cmd.Email))

	// 1. VO Conversion
	email, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return ZeroLoginResponse, err
	}

	rawPassword, err := domain.NewRawPassword(cmd.Password)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 2. Fetch Aggregate
	user, err := uc.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return ZeroLoginResponse, err
	}
	if user == nil {
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
	// No more manual timing or role mapping here!
	accessToken, accessExpiry, err := uc.accessManager.GrantImmediateAccess(user, session.ID(), now)
	if err != nil {
		logger.Error("access_grant_failed", slog.Any("error", err))
		return ZeroLoginResponse, err
	}

	// 5. Persistence
	if err := uc.userRepo.Save(ctx, user); err != nil {
		return ZeroLoginResponse, err
	}

	logger.Info("login_success", slog.String("user_id", user.ID().String()))

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  accessExpiry.String(),
		RefreshToken:       rawRefreshToken.String(),
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}

// --- Refresh Token Use Case ---
type refreshTokenUseCase struct {
	userRepo      domain.IUserRepository
	authSvc       domain.IAuthenticationService
	accessManager domain.IAccessManager
	clock         domain.IClock
}

func NewRefreshTokenUseCase(
	userRepo domain.IUserRepository,
	authSvc domain.IAuthenticationService,
	accessManager domain.IAccessManager,
	clock domain.IClock,
) IRefreshTokenUseCase {
	return &refreshTokenUseCase{
		userRepo:      userRepo,
		authSvc:       authSvc,
		accessManager: accessManager,
		clock:         clock,
	}
}

func (uc *refreshTokenUseCase) Execute(ctx context.Context, cmd RefreshTokenCommand) (LoginResponse, error) {
	// 1. VO Conversion
	raw, err := domain.NewRawToken(cmd.RefreshToken)
	if err != nil {
		return ZeroLoginResponse, err
	}

	fp, err := domain.NewDeviceFingerprint(cmd.Fingerprint)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 2. Domain Service Coordination
	now := uc.clock.Now()
	user, session, err := uc.authSvc.RefreshSession(ctx, raw, fp, now)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 3. Access Manager Coordination
	accessToken, accessExpiry, err := uc.accessManager.GrantImmediateAccess(user, session.ID(), now)
	if err != nil {
		return ZeroLoginResponse, err
	}

	// 4. Atomic Persistence
	if err := uc.userRepo.Save(ctx, user); err != nil {
		return ZeroLoginResponse, err
	}

	return LoginResponse{
		AccessToken:        accessToken.String(),
		AccessTokenExpiry:  accessExpiry.String(),
		RefreshToken:       cmd.RefreshToken,
		RefreshTokenExpiry: session.ExpiresAt().String(),
	}, nil
}

// --- Validate Access Use Case ---
type validateAccessUseCase struct {
	accessManager domain.IAccessManager
	clock         domain.IClock
}

func NewValidateAccessUseCase(
	accessManager domain.IAccessManager,
	clock domain.IClock,
) IValidateAccessUseCase {
	return &validateAccessUseCase{
		accessManager: accessManager,
		clock:         clock,
	}
}

func (uc *validateAccessUseCase) Execute(ctx context.Context, query ValidateAccessQuery) (ValidateAccessResponse, error) {
	// 1. VO Conversion
	token, err := domain.NewAccessToken(query.AccessToken)
	if err != nil {
		return ZeroValidateAccessResponse, err
	}

	// 2. Delegate to Domain Service
	// This encapsulates: Crypto check -> User Fetch -> Session Integrity
	now := uc.clock.Now()
	user, sid, err := uc.accessManager.VerifyAccess(ctx, token, now)
	if err != nil {
		// We log it, but we return a generic domain error for security
		return ZeroValidateAccessResponse, err
	}

	// 3. Response Formatting
	return ValidateAccessResponse{
		UserID:    user.ID().String(),
		SessionID: sid.String(),
		Roles:     user.RoleNames(),
	}, nil
}

type logoutUseCase struct {
	userRepo domain.IUserRepository
	clock    domain.IClock
}

func NewLogoutUseCase(
	repo domain.IUserRepository,
	clock domain.IClock,
) ILogoutUseCase {
	return &logoutUseCase{
		userRepo: repo,
		clock:    clock,
	}
}

func (uc *logoutUseCase) Execute(ctx context.Context, cmd LogoutCommand) error {
	// 1. VO Conversion (Fail Fast)
	uid, err := domain.NewUserID(cmd.UserID)
	if err != nil {
		return err
	}

	sid, err := domain.NewSessionID(cmd.SessionID)
	if err != nil {
		return err
	}

	// 2. Identity Resolution
	// We fetch the Aggregate Root from the infrastructure
	user, err := uc.userRepo.FindByID(ctx, uid)
	if err != nil {
		return err
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	// 3. THE DOMAIN LOGIC (Direct Aggregate Method)
	// The User aggregate handles the business rule:
	// "Mark this specific session as revoked and update the aggregate timestamp."
	now := uc.clock.Now()
	if err := user.RevokeSession(sid, now); err != nil {
		// If the session is already revoked or doesn't exist, the Aggregate tells us.
		GetLogger(ctx).Warn("logout_rejected_by_aggregate",
			slog.String("session_id", sid.String()),
			slog.Any("error", err),
		)
		return err
	}

	// 4. Persistence
	// The Repository commits the entire Aggregate state back to the store.
	if err := uc.userRepo.Save(ctx, user); err != nil {
		return err
	}

	GetLogger(ctx).Info("logout_successful")

	return nil
}

// --- Fetch User Use Case ---
type findUserByEmailUseCase struct {
	userRepo domain.IUserRepository
}

func NewFindUserByEmailUseCase(repo domain.IUserRepository) IFindUserByEmailUseCase {
	return &findUserByEmailUseCase{userRepo: repo}
}

func (uc *findUserByEmailUseCase) Execute(ctx context.Context, email string) (UserResponse, error) {
	logger := GetLogger(ctx)

	// 1. Convert primitive string to Domain Value Object
	emailVO, err := domain.NewEmail(email)
	if err != nil {
		return ZeroUserResponse, err
	}

	// 2. Query Repository
	user, err := uc.userRepo.FindByEmail(ctx, emailVO)
	if err != nil {
		logger.Error("repo_lookup_failed", slog.String("email", email), slog.Any("error", err))
		return ZeroUserResponse, err
	}

	if user == nil {
		return ZeroUserResponse, ErrResourceNotFound
	}

	// 3. Return DTO (Not the Entity)
	return UserResponse{
		ID:    user.ID().String(),
		Email: user.Email().String(),
	}, nil
}

type getUserByIDUseCase struct {
	userRepo domain.IUserRepository
}

func NewGetUserByIDUseCase(repo domain.IUserRepository) IGetUserByIDUseCase {
	return &getUserByIDUseCase{userRepo: repo}
}

func (uc *getUserByIDUseCase) Execute(ctx context.Context, id string) (UserResponse, error) {
	logger := GetLogger(ctx)

	// 1. Domain-level ID validation
	userID, err := domain.NewUserID(id)
	if err != nil {
		return ZeroUserResponse, err
	}

	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		logger.Error("repo_id_lookup_failed", slog.String("id", id), slog.Any("error", err))
		return ZeroUserResponse, err
	}

	if user == nil {
		return ZeroUserResponse, ErrResourceNotFound
	}

	return UserResponse{
		ID:    user.ID().String(),
		Email: user.Email().String(),
	}, nil
}

type getMeUseCase struct {
	userRepo domain.IUserRepository
}

func NewGetMeUseCase(repo domain.IUserRepository) IGetMeUseCase {
	return &getMeUseCase{userRepo: repo}
}

func (uc *getMeUseCase) Execute(ctx context.Context, id string) (UserResponse, error) {
	logger := GetLogger(ctx)

	userID, err := domain.NewUserID(id)
	if err != nil {
		return ZeroUserResponse, err
	}

	user, err := uc.userRepo.FindByID(ctx, userID)
	if err != nil {
		logger.Error("me_lookup_failed", slog.String("user_id", id), slog.Any("error", err))
		return ZeroUserResponse, err
	}

	if user == nil {
		return ZeroUserResponse, ErrResourceNotFound
	}

	return UserResponse{
		ID:    user.ID().String(),
		Email: user.Email().String(),
	}, nil
}

type updateMeUseCase struct {
	userRepo domain.IUserRepository
	clock    domain.IClock
}

func NewUpdateMeUseCase(
	repo domain.IUserRepository,
	clock domain.IClock,
) IUpdateMeUseCase {
	return &updateMeUseCase{
		userRepo: repo,
		clock:    clock,
	}
}

func (uc *updateMeUseCase) Execute(ctx context.Context, cmd UpdateMeCommand) error {
	uid := GetUserID(ctx)
	if uid.IsEmpty() {
		return ErrUnauthorized
	}

	emailVO, err := domain.NewEmail(cmd.Email)
	if err != nil {
		return err
	}

	user, err := uc.userRepo.FindByID(ctx, uid)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrResourceNotFound
	}

	if !user.Email().Equal(emailVO) {
		existing, err := uc.userRepo.FindByEmail(ctx, emailVO)
		if err != nil {
			return err
		}
		if existing != nil {
			return domain.ErrUserEmailTaken
		}
	}

	if err := user.UpdateEmail(emailVO, uc.clock.Now()); err != nil {
		return err
	}

	return uc.userRepo.Save(ctx, user)
}

type changePasswordUseCase struct {
	userRepo       domain.IUserRepository
	accountManager domain.IUserAccountManager
	clock          domain.IClock
}

func NewChangePasswordUseCase(
	userRepo domain.IUserRepository,
	accountManager domain.IUserAccountManager,
	clock domain.IClock,
) IChangePasswordUseCase {
	return &changePasswordUseCase{
		userRepo:       userRepo,
		accountManager: accountManager,
		clock:          clock,
	}
}

func (uc *changePasswordUseCase) Execute(ctx context.Context, cmd ChangePasswordCommand) error {
	// 1. Resolve Identity
	uid := GetUserID(ctx)
	if uid.IsEmpty() {
		return ErrUnauthorized
	}

	// 2. Fetch Aggregate
	user, err := uc.userRepo.FindByID(ctx, uid)
	if err != nil || user == nil {
		return ErrResourceNotFound
	}

	// 3. Value Object Conversion
	oldPass, err := domain.NewRawPassword(cmd.OldPassword)
	if err != nil {
		return err
	}

	newPass, err := domain.NewRawPassword(cmd.NewPassword)
	if err != nil {
		return err
	}

	// 4. Delegate to Domain Manager
	// All hashing/comparing is hidden behind this Domain Service
	now := uc.clock.Now()
	if err := uc.accountManager.ChangePassword(
		ctx,
		user,
		oldPass,
		newPass,
		now,
	); err != nil {
		return err
	}

	// 5. Persistence
	return uc.userRepo.Save(ctx, user)
}

// Reset Password
type resetPasswordUseCase struct {
	accountMgr domain.IUserAccountManager
	txManager  ITransactionManager
	clock      domain.IClock
}

func NewResetPasswordUseCase(
	accountMgr domain.IUserAccountManager,
	txManager ITransactionManager,
	clock domain.IClock,
) IResetPasswordUseCase {
	return &resetPasswordUseCase{
		accountMgr: accountMgr,
		txManager:  txManager,
		clock:      clock,
	}
}
func (uc *resetPasswordUseCase) Execute(ctx context.Context, cmd ResetPasswordCommand) error {
	// 1. VO Conversion
	rawToken, err := domain.NewRawToken(cmd.Token)
	if err != nil {
		return err
	}

	rawPassword, err := domain.NewRawPassword(cmd.NewPassword)
	if err != nil {
		return err
	}

	// 2. Transaction Orchestration
	// Evans: The Application Layer coordinates the transaction boundary.
	return uc.txManager.WithTransaction(ctx, func(txCtx context.Context) error {
		return uc.accountMgr.ResetPasswordByToken(
			txCtx,
			rawToken,
			rawPassword,
			uc.clock.Now(),
		)
	})
}

// Forget Password
type forgotPasswordUseCase struct {
	userRepository     domain.IUserRepository
	recoveryRepository domain.IRecoveryTokenRepository
	accountManager     domain.IUserAccountManager
	emailService       IEmailService
	transactionManager ITransactionManager
	clock              domain.IClock
}

func NewForgotPasswordUseCase(
	userRepository domain.IUserRepository,
	recoveryRepository domain.IRecoveryTokenRepository,
	accountManager domain.IUserAccountManager,
	emailService IEmailService,
	transactionManager ITransactionManager,
	clock domain.IClock,
) IForgotPasswordUseCase {
	return &forgotPasswordUseCase{
		userRepository:     userRepository,
		recoveryRepository: recoveryRepository,
		accountManager:     accountManager,
		emailService:       emailService,
		transactionManager: transactionManager,
		clock:              clock,
	}
}

func (useCase *forgotPasswordUseCase) Execute(
	ctx context.Context,
	command ForgotPasswordCommand,
) error {
	// 1. Value Object Conversion: Fail fast before entering the DB layer.
	email, err := domain.NewEmail(command.Email)
	if err != nil {
		return err
	}

	// 2. Resolve Aggregate: Fetch the subject of the operation.
	user, err := useCase.userRepository.FindByEmail(ctx, email)
	if err != nil {
		return err
	}

	// 3. Security Boundary: If user doesn't exist, we return nil.
	// This prevents account enumeration by treating "not found" as success.
	if user == nil {
		return nil
	}

	var rawToken domain.RawToken

	// 4. Transactional Boundary: Managing persistence of Domain changes.
	err = useCase.transactionManager.WithTransaction(ctx, func(txCtx context.Context) error {
		// A. Ask the Domain Service to prepare the recovery state.
		// It returns the Secret (RawToken) and the Aggregate (RecoveryToken).
		raw, recoveryToken, err := useCase.accountManager.InitiatePasswordReset(
			txCtx,
			user,
			useCase.clock.Now(),
		)
		if err != nil {
			return err
		}

		// Capture the raw secret to be used outside the transaction later.
		rawToken = raw

		// B. Persist the newly created Aggregate.
		// As per Evans: The Domain Service creates the state; the Use Case saves it.
		return useCase.recoveryRepository.Save(txCtx, recoveryToken)
	})

	if err != nil {
		return err
	}

	// 5. Infrastructure side-effect: Send the RawToken to the user.
	// We do this AFTER a successful commit to ensure the token exists in our DB.
	return useCase.emailService.SendResetLink(user.Email().String(), rawToken.String())
}
