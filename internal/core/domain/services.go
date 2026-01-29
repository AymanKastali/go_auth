package domain

import (
	"context"
)

// --- Authenticate User Service ---
type authenticateUserService struct {
	userRepo    IUserRepository
	passwordSvc IPasswordService
}

func NewAuthenticateUserService(repo IUserRepository, pwSvc IPasswordService) IAuthenticateUser {
	return &authenticateUserService{
		userRepo:    repo,
		passwordSvc: pwSvc,
	}
}

func (s *authenticateUserService) Execute(ctx context.Context, email Email, password RawPassword) (*User, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	// Security: Generic "Authentication Failed" to prevent enumeration
	if user == nil {
		return nil, ErrAuthenticationFailed
	}

	if !s.passwordSvc.Compare(password, user.HashedPassword()) {
		return nil, ErrAuthenticationFailed
	}

	return user, nil
}

// --- Establish User Session Service ---
type establishUserSessionService struct {
	sessionFactory ISessionFactory
	sessionPolicy  ISessionPolicy
	clock          IClock
	idGen          IIDGenerator
	tokenService   ITokenService
}

func NewEstablishUserSessionService(
	factory ISessionFactory,
	policy ISessionPolicy,
	clock IClock,
	idGen IIDGenerator,
	tokenSvc ITokenService,
) IEstablishUserSession {
	return &establishUserSessionService{
		sessionFactory: factory,
		sessionPolicy:  policy,
		clock:          clock,
		idGen:          idGen,
		tokenService:   tokenSvc,
	}
}

func (s *establishUserSessionService) Execute(ctx context.Context, user *User, deviceIdentity DeviceIdentity) (*Session, RawToken, error) {
	now := s.clock.Now()

	// 1. Identify Existing Session
	var sid SessionID
	for _, existing := range user.Sessions() {
		if existing.Identity().Fingerprint().Equal(deviceIdentity.Fingerprint()) && !existing.IsRevoked() {
			sid = existing.ID()
			break
		}
	}

	// 2. ID Generation
	if sid.IsEmpty() {
		var err error
		sid, err = s.idGen.GenerateSessionID()
		if err != nil {
			return nil, ZeroRawToken, err
		}
	}

	// 3. Security Materials
	rawToken, err := s.tokenService.Generate()
	if err != nil {
		return nil, ZeroRawToken, err
	}

	hashedToken, err := s.tokenService.Hash(rawToken)
	if err != nil {
		return nil, ZeroRawToken, err
	}

	// 4. Build Session
	expiresAt := now.Add(s.sessionPolicy.GetSessionLifetime())
	session, err := s.sessionFactory.Build(sid, hashedToken, deviceIdentity, expiresAt, now)
	if err != nil {
		return nil, ZeroRawToken, err // Returns ErrSessionExpiryInPast etc.
	}

	// 5. Delegate to Aggregate
	if err := user.EstablishSession(*session, s.sessionPolicy.GetMaxActiveSessions()); err != nil {
		return nil, ZeroRawToken, err
	}

	return session, rawToken, nil
}

// --- Refresh Session Service ---
type refreshSessionService struct {
	userRepo     IUserRepository
	tokenService ITokenService
	clock        IClock
}

func NewRefreshSessionService(repo IUserRepository, tokenSvc ITokenService, clock IClock) IRefreshSession {
	return &refreshSessionService{
		userRepo:     repo,
		tokenService: tokenSvc,
		clock:        clock,
	}
}

func (s *refreshSessionService) Execute(ctx context.Context, raw RawToken, currentFingerprint DeviceFingerprint) (*User, Session, error) {
	hashed, err := s.tokenService.Hash(raw)
	if err != nil {
		return nil, ZeroSession, err
	}

	user, err := s.userRepo.FindBySessionToken(ctx, hashed)
	if err != nil {
		return nil, ZeroSession, err
	}

	if user == nil {
		return nil, ZeroSession, ErrTokenInvalid // Explicit
	}

	now := s.clock.Now()
	// Returns ErrSessionFingerprintMiss or ErrTokenRevoked
	session, err := user.RefreshSession(hashed, currentFingerprint, now)
	if err != nil {
		return nil, ZeroSession, err
	}

	return user, session, nil
}

// Access Granter
type accessGrantor struct {
	accessTokenSvc IAccessTokenService
	policy         IAccessPolicy
	clock          IClock
}

func NewAccessGrantor(
	accessTokenSvc IAccessTokenService,
	policy IAccessPolicy,
	clock IClock,
) IAccessGrantor {
	return &accessGrantor{
		accessTokenSvc: accessTokenSvc,
		policy:         policy,
		clock:          clock,
	}
}

func (s *accessGrantor) GrantImmediateAccess(
	ctx context.Context,
	user *User,
	sessionID SessionID,
) (AccessToken, Timepoint, error) {
	now := s.clock.Now()
	issuedAt := now
	expiresAt := issuedAt.Add(s.policy.GetAccessLifetime())
	notBefore := issuedAt
	return s.accessTokenSvc.Issue(
		user.ID(),
		user.Email(),
		sessionID,
		user.Roles(),
		issuedAt,
		expiresAt,
		notBefore,
	)
}

// Access Granter
type changePassword struct {
	userRepo    IUserRepository
	passwordSvc IPasswordService
	policy      IPasswordPolicy
	clock       IClock
}

func NewChangePassword(
	userRepo IUserRepository,
	passwordSvc IPasswordService,
	policy IPasswordPolicy,
	clock IClock,
) IChangePassword {
	return &changePassword{
		userRepo:    userRepo,
		passwordSvc: passwordSvc,
		policy:      policy,
		clock:       clock,
	}
}

func (s *changePassword) ChangePassword(
	ctx context.Context,
	user *User,
	oldPassword RawPassword,
	newPassword RawPassword,
) error {
	// 1. Verify Ownership/Knowledge of existing credential
	if !s.passwordSvc.Compare(oldPassword, user.HashedPassword()) {
		return ErrAuthenticationFailed
	}

	// 2. Enforce complexity/policy invariants
	if err := s.policy.Validate(newPassword); err != nil {
		return err
	}

	// 3. Transform Raw to Hashed
	newHash, err := s.passwordSvc.Hash(newPassword)
	if err != nil {
		return err
	}

	// 4. Update Aggregate state (this will also revoke sessions)
	return user.UpdatePassword(newHash, s.clock.Now())
}

// Password Reset Service
type passwordResetService struct {
	userRepo     IUserRepository
	recoveryRepo IRecoveryTokenRepository
	tokenSvc     ITokenService
	passwordSvc  IPasswordService
	pwPolicy     IPasswordPolicy
}

func NewPasswordResetService(
	ur IUserRepository,
	rr IRecoveryTokenRepository,
	ts ITokenService,
	ps IPasswordService,
	pp IPasswordPolicy,
) IPasswordResetService {
	return &passwordResetService{
		userRepo:     ur,
		recoveryRepo: rr,
		tokenSvc:     ts,
		passwordSvc:  ps,
		pwPolicy:     pp,
	}
}

func (s *passwordResetService) Reset(
	ctx context.Context,
	rawToken RawToken,
	newPassword RawPassword,
	now Timepoint,
) error {
	// 1. Hashing for DB Lookup
	hashedToken, err := s.tokenSvc.Hash(rawToken)
	if err != nil {
		return ErrInternal
	}

	// 2. Find and Validate the Recovery Token
	recovery, err := s.recoveryRepo.FindByHash(ctx, ReconstituteRecoveryTokenHash(hashedToken.String()))
	if err != nil {
		return err
	}
	if recovery == nil || !recovery.IsValid(now) {
		return ErrRecoveryTokenInvalid
	}

	// 3. Find the User
	user, err := s.userRepo.FindByID(ctx, recovery.UserID())
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// 4. Policy Check
	if err := s.pwPolicy.Validate(newPassword); err != nil {
		return err
	}

	// 5. Hash the Password
	newHashedPw, err := s.passwordSvc.Hash(newPassword)
	if err != nil {
		return ErrInternal
	}

	// 6. Update Aggregates (Domain State changes)
	if err := user.UpdatePassword(newHashedPw, now); err != nil {
		return err
	}
	if err := recovery.MarkAsUsed(now); err != nil {
		return err
	}

	// 7. Persist changes
	if err := s.userRepo.Save(ctx, user); err != nil {
		return err
	}
	return s.recoveryRepo.Save(ctx, recovery)
}

// --- Forgot Password Service ---
type forgotPasswordService struct {
	recoveryRepo   IRecoveryTokenRepository
	tokenSvc       ITokenService
	idGen          IIDGenerator
	recoveryPolicy IRecoveryPolicy // Added to match your Policy pattern
}

func NewForgotPasswordService(
	rr IRecoveryTokenRepository,
	ts ITokenService,
	idGen IIDGenerator,
	rp IRecoveryPolicy,
) IForgotPasswordService {
	return &forgotPasswordService{
		recoveryRepo:   rr,
		tokenSvc:       ts,
		idGen:          idGen,
		recoveryPolicy: rp,
	}
}

func (s *forgotPasswordService) Execute(
	ctx context.Context,
	user *User,
	now Timepoint,
) (RawToken, error) {
	// 1. Generate ID for the new Recovery Token Aggregate
	tid, err := s.idGen.GenerateRecoveryTokenID()
	if err != nil {
		return ZeroRawToken, err
	}

	// 2. Security Materials
	raw, err := s.tokenSvc.Generate()
	if err != nil {
		return ZeroRawToken, ErrInternal
	}

	hashed, err := s.tokenSvc.Hash(raw)
	if err != nil {
		return ZeroRawToken, ErrInternal
	}

	// 3. Clean up: Revoke any existing tokens for this user
	if err := s.recoveryRepo.RevokeAllForUser(ctx, user.ID(), now); err != nil {
		return ZeroRawToken, err
	}

	// 4. Build the RecoveryToken Aggregate
	// Use the Policy to determine expiry, similar to establishUserSessionService
	expiresAt := now.Add(s.recoveryPolicy.GetRecoveryTokenLifetime())

	token, err := NewRecoveryToken(
		tid,
		user.ID(),
		ReconstituteRecoveryTokenHash(hashed.String()),
		expiresAt,
		now,
	)
	if err != nil {
		return ZeroRawToken, err
	}

	// 5. Persist the record
	if err := s.recoveryRepo.Save(ctx, token); err != nil {
		return ZeroRawToken, err
	}

	return raw, nil
}
