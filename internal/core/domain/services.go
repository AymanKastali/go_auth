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

func NewUserRegistrationService(
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
	id, err := s.idGen.GenerateUserID()
	if err != nil {
		return nil, err
	}

	user, err := s.userFactory.Build(id, email, hashed, s.clock.Now())
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
	sid, err := s.idGen.GenerateSessionID()
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

type refreshUserSessionService struct {
	tokenService ITokenService
	clock        IClock
}

func NewRefreshUserSessionService(
	clock IClock,
	tokenService ITokenService,
) IRefreshUserSession {
	return &refreshUserSessionService{
		clock:        clock,
		tokenService: tokenService,
	}
}

func (s *refreshUserSessionService) Execute(
	ctx context.Context,
	user *User,
	raw RawToken,
	currentFingerprint DeviceFingerprint,
) (*User, Session, error) {
	hashed, err := s.tokenService.Hash(raw)
	if err != nil {
		return nil, ZeroSession, err
	}

	now := s.clock.Now()
	// We need the aggregate to return the session it just validated
	session, err := user.RefreshSession(hashed, currentFingerprint, now)
	if err != nil {
		return nil, ZeroSession, err
	}

	return user, session, nil
}

// Access Session For User
// Authentication Service
type accessGrantor struct {
	tokenService IAccessTokenService
	policy       IAccessPolicy
	clock        IClock
}

func NewAccessGrantor(
	tokenService IAccessTokenService,
	policy IAccessPolicy,
	clock IClock,
) IAccessGrantor {
	return &accessGrantor{
		tokenService: tokenService,
		policy:       policy,
		clock:        clock,
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
	return s.tokenService.Issue(
		user.ID(),
		user.Email(),
		sessionID,
		user.Roles(),
		issuedAt,
		expiresAt,
		notBefore,
	)
}
