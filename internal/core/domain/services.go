package domain

import (
	"context"
)

// Registration Service
type userRegistrationService struct {
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
) IUserRegistrationService {
	return &userRegistrationService{
		userRepo:       repo,
		passwordPolicy: policy,
		passwordSvc:    pwdSvc,
		userFactory:    factory,
		idGen:          idGen,
		clock:          clock,
	}
}

func (s *userRegistrationService) Register(
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
	existing, _ := s.userRepo.FindByEmail(ctx, email)
	if existing != nil {
		return nil, NewEmailAlreadyTakenError(email.String())
	}

	// 3. Use the internal service to hash
	hashed, err := s.passwordSvc.Hash(password)
	if err != nil {
		return nil, err
	}

	// 4. Build the user
	id, err := s.idGen.GenerateUserID(ctx)
	if err != nil {
		return nil, err
	}

	user, err := s.userFactory.Build(id, email, hashed, s.clock.Now())
	if err != nil {
		return nil, err
	}

	// Assign the static VO role
	user.AssignRole(RoleMember)

	// Pass the required Timepoint
	user.Activate(now)

	return user, nil
}

// Authentication Service
type authenticationService struct {
	userRepo       IUserRepository
	passwordSvc    IPasswordService
	tokenSvc       ITokenService
	sessionFactory ISessionFactory
	sessionPolicy  ISessionPolicy
	clock          IClock
	idGen          IIDGenerator
}

func NewAuthenticationService(
	userRepo IUserRepository,
	passwordSvc IPasswordService,
	tokenSvc ITokenService,
	sessionFactory ISessionFactory,
	sessionPolicy ISessionPolicy,
	clock IClock,
	idGen IIDGenerator,
) IAuthenticationService {
	return &authenticationService{
		userRepo:       userRepo,
		passwordSvc:    passwordSvc,
		tokenSvc:       tokenSvc,
		sessionFactory: sessionFactory,
		sessionPolicy:  sessionPolicy,
		clock:          clock,
		idGen:          idGen,
	}
}

func (s *authenticationService) Authenticate(
	ctx context.Context,
	email Email,
	password RawPassword,
	fp DeviceFingerprint,
	ua string,
	ip string,
) (*User, Session, RawToken, error) {
	// 1. Fetch the Aggregate Root
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}

	// 2. Business Logic: Verify Password
	if !s.passwordSvc.Compare(password, user.HashedPassword()) {
		return nil, ZeroSession, ZeroRawToken, NewInvalidCredentialsError()
	}

	// 3. Prepare Session Data
	now := s.clock.Now()
	expiry := now.Add(s.sessionPolicy.GetExpiryDuration())
	sid, err := s.idGen.GenerateSessionID(ctx)
	if err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}

	rawT, hashedT, err := s.tokenSvc.Generate()
	if err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}

	// 4. Use "Dumb" Factory to assemble the Session entity
	session, err := s.sessionFactory.Build(sid, hashedT, fp, ua, ip, expiry, now)
	if err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}

	// 5. Update the Aggregate Root
	// Note: We need a method on the User aggregate to handle this!
	if err := user.AddSession(*session, s.sessionPolicy.GetMaxActiveSessions()); err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}

	return user, *session, rawT, nil
}

func (s *authenticationService) RefreshUserSession(
	ctx context.Context,
	uid UserID,
	raw RawToken,
	fp DeviceFingerprint,
) (*User, Session, error) {
	user, err := s.userRepo.FindByID(ctx, uid)
	if err != nil {
		return nil, ZeroSession, err
	}

	hashed, err := s.tokenSvc.Hash(raw)
	if err != nil {
		return nil, ZeroSession, err
	}

	now := s.clock.Now()
	// We need the aggregate to return the session it just validated
	session, err := user.RefreshSession(hashed, fp, now)
	if err != nil {
		return nil, ZeroSession, err
	}

	return user, session, nil
}

// Identity Guard Service
type identityGuardService struct {
	clock IClock
}

func NewIdentityGuardService(clock IClock) IIdentityGuardService {
	return &identityGuardService{clock: clock}
}

func (s *identityGuardService) CheckIntegrity(user *User, sid SessionID) error {
	now := s.clock.Now()
	if user == nil {
		return NewUserNotFoundError(user.ID().String())
	}

	if !user.IsActive() {
		return NewUserInactiveError(user.ID().String())
	}

	if user.IsDeleted() {
		return NewUserDeletedError(user.ID().String())
	}

	// Check if the specific session is valid (not revoked/expired)
	if !user.HasActiveSession(sid, now) {
		return NewSessionInvalidError(sid.String())
	}

	return nil
}
