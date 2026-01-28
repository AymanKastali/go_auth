package domain

import (
	"context"
)

// Registration Service
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
	pwdSvc IPasswordService,
	factory IUserFactory,
	idGen IIDGenerator,
	clock IClock,
) IRegisterUserService {
	return &registerUserService{
		userRepo:       repo,
		passwordPolicy: policy,
		passwordSvc:    pwdSvc,
		userFactory:    factory,
		idGen:          idGen,
		clock:          clock,
	}
}

func (s *registerUserService) Execute(
	ctx context.Context,
	email Email,
	password RawPassword,
) (*User, error) {
	now := s.clock.Now()

	// 1. Policy check
	if err := s.passwordPolicy.Validate(password); err != nil {
		return nil, err
	}

	// 2. Uniqueness check
	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if existing != nil {
		return nil, NewEmailAlreadyTakenError(email.String())
	}

	// 3. Use the internal service to hash
	hashed, err := s.passwordSvc.Hash(password)
	if err != nil {
		return nil, err
	}

	// 4. Build the user
	id, err := s.idGen.Generate()
	if err != nil {
		return nil, err
	}

	uid, err := NewUserID(id)
	if err != nil {
		return nil, err
	}

	user, err := s.userFactory.Build(uid, email, hashed, s.clock.Now())
	if err != nil {
		return nil, err
	}

	// Assign the static VO role
	if err := user.AssignRole(RoleMember, now); err != nil {
		return nil, err
	}

	// Pass the required Timepoint
	if err := user.Activate(now); err != nil {
		return nil, err
	}

	return user, nil
}

// Authenticate User Service
type authenticateUserService struct {
	userRepo    IUserRepository
	passwordSvc IPasswordService
}

func NewAuthenticateUserService(
	userRepo IUserRepository,
	passwordSvc IPasswordService,
) IAuthenticateUser {
	return &authenticateUserService{
		userRepo:    userRepo,
		passwordSvc: passwordSvc,
	}
}

func (s *authenticateUserService) Execute(
	ctx context.Context,
	email Email,
	password RawPassword,
) (*User, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, NewInvalidCredentialsError()
	}

	// 2. Business Logic: Verify Password
	if !s.passwordSvc.Compare(password, user.HashedPassword()) {
		return nil, NewInvalidCredentialsError()
	}

	return user, nil
}

// Establish User Session

type establishUserSessionService struct {
	sessionFactory ISessionFactory
	sessionPolicy  ISessionPolicy
	clock          IClock
	idGen          IIDGenerator
	tokenService   ITokenService
}

func NewEstablishUserSessionService(
	sessionFactory ISessionFactory,
	sessionPolicy ISessionPolicy,
	clock IClock,
	idGen IIDGenerator,
	tokenService ITokenService,
) IEstablishUserSession {
	return &establishUserSessionService{
		sessionFactory: sessionFactory,
		sessionPolicy:  sessionPolicy,
		clock:          clock,
		idGen:          idGen,
		tokenService:   tokenService,
	}
}

func (s *establishUserSessionService) Execute(
	ctx context.Context,
	user *User,
	deviceIdentity DeviceIdentity,
) (*Session, RawToken, error) {
	id, err := s.idGen.Generate()
	if err != nil {
		return nil, ZeroRawToken, err
	}

	sid, err := NewSessionID(id)
	if err != nil {
		return nil, ZeroRawToken, err
	}

	rawToken, err := s.tokenService.Generate()
	if err != nil {
		return nil, ZeroRawToken, err
	}
	hashedToken, err := s.tokenService.Hash(rawToken)
	if err != nil {
		return nil, ZeroRawToken, err
	}
	now := s.clock.Now()
	expiresAt := now.Add(s.sessionPolicy.GetSessionLifetime())

	session, err := s.sessionFactory.Build(sid, hashedToken, deviceIdentity, expiresAt, now)
	if err != nil {
		return nil, ZeroRawToken, err
	}

	err = user.EstablishSession(*session, s.sessionPolicy.GetMaxActiveSessions())
	if err != nil {
		return nil, ZeroRawToken, err
	}

	return session, rawToken, nil
}

type refreshSessionService struct {
	userRepo     IUserRepository
	tokenService ITokenService
	clock        IClock
}

func NewRefreshSessionService(
	userRepo IUserRepository,
	tokenService ITokenService,
	clock IClock,
) IRefreshSession {
	return &refreshSessionService{
		userRepo:     userRepo,
		tokenService: tokenService,
		clock:        clock,
	}
}

func (s *refreshSessionService) Execute(
	ctx context.Context,
	raw RawToken,
	currentFingerprint DeviceFingerprint,
) (*User, Session, error) {
	// 1. Hash the raw token provided by the client
	hashed, err := s.tokenService.Hash(raw)
	if err != nil {
		return nil, ZeroSession, err
	}

	// 2. Resolve Identity: Find the User Aggregate owning this session
	user, err := s.userRepo.FindBySessionToken(ctx, hashed)
	if err != nil {
		return nil, ZeroSession, err
	}
	if user == nil {
		// Security: Return a generic error to prevent session probing
		return nil, ZeroSession, NewInvalidTokenError()
	}

	// 3. Delegate logic to the Aggregate
	now := s.clock.Now()
	session, err := user.RefreshSession(hashed, currentFingerprint, now)
	if err != nil {
		return nil, ZeroSession, err
	}

	return user, session, nil
}

// Access Session For User
// Authentication Service
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
