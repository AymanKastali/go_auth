package domain

import (
	"context"
)

// --- Registration Service ---
type registerUserService struct {
	userRepo       IUserRepository
	passwordPolicy IPasswordPolicy
	passwordSvc    IPasswordService
	userFactory    IUserFactory
	idGen          IIDGenerator
	clock          IClock
}

func NewRegisterUserService(
	repo IUserRepository,
	policy IPasswordPolicy,
	pwSvc IPasswordService,
	factory IUserFactory,
	idGen IIDGenerator,
	clock IClock,
) IRegisterUserService {
	return &registerUserService{
		userRepo:       repo,
		passwordPolicy: policy,
		passwordSvc:    pwSvc,
		userFactory:    factory,
		idGen:          idGen,
		clock:          clock,
	}
}

func (s *registerUserService) Execute(ctx context.Context, email Email, password RawPassword) (*User, error) {
	now := s.clock.Now()

	// 1. Policy check (returns explicit ErrPassword... sentinels)
	if err := s.passwordPolicy.Validate(password); err != nil {
		return nil, err
	}

	// 2. Uniqueness check
	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserEmailTaken // Explicit
	}

	// 3. Logic: Hash and Build
	hashed, err := s.passwordSvc.Hash(password)
	if err != nil {
		return nil, err
	}

	id, err := s.idGen.Generate()
	if err != nil {
		return nil, err
	}

	uid, err := NewUserID(id)
	if err != nil {
		return nil, err // Returns ErrUserIDRequired
	}

	user, err := s.userFactory.Build(uid, email, hashed, now)
	if err != nil {
		return nil, err
	}

	if err := user.AssignRole(RoleMember, now); err != nil {
		return nil, err
	}

	if err := user.Activate(now); err != nil {
		return nil, err
	}

	return user, nil
}

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
		id, err := s.idGen.Generate()
		if err != nil {
			return nil, ZeroRawToken, err
		}
		sid, err = NewSessionID(id)
		if err != nil {
			return nil, ZeroRawToken, err // Returns ErrSessionIDRequired
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
