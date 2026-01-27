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
	id, err := s.idGen.GenerateUserID(ctx)
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
	identity DeviceIdentity,
) (*User, Session, RawToken, error) {
	// 1. Fetch the Aggregate Root
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}
	if user == nil {
		return nil, ZeroSession, ZeroRawToken, NewInvalidCredentialsError()
	}

	// 2. Business Logic: Verify Password
	if !s.passwordSvc.Compare(password, user.HashedPassword()) {
		return nil, ZeroSession, ZeroRawToken, NewInvalidCredentialsError()
	}

	// 3. Prepare fresh credentials and timestamps
	now := s.clock.Now()
	expiry := now.Add(s.sessionPolicy.GetSessionLifetime())

	// We generate a "potential" SessionID and HashedToken.
	// If it's a new device, these are used.
	// If it's an existing device, the token is rotated but the SessionID might be ignored
	// depending on your preference (usually we keep the SessionID or rotate both).
	sid, err := s.idGen.GenerateSessionID(ctx)
	if err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}

	rawT, hashedT, err := s.tokenSvc.Generate()
	if err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}

	// 4. Build the "Candidate" Session
	candidateSession, err := s.sessionFactory.Build(
		sid,
		hashedT,
		identity,
		expiry,
		now,
	)
	if err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}

	// 5. Let the Aggregate decide: Update existing or Add new
	err = user.Login(*candidateSession, s.sessionPolicy.GetMaxActiveSessions())
	if err != nil {
		return nil, ZeroSession, ZeroRawToken, err
	}

	// 6. Retrieve the actual session from the aggregate to return to the caller.
	// This ensures that if the aggregate updated an existing session, we return
	// that specific session (with its original ID) instead of the 'candidate' one.
	var finalSession Session
	for _, session := range user.Sessions() {
		if session.Identity().Fingerprint().Equal(identity.Fingerprint()) && !session.IsRevoked() {
			finalSession = session
			break
		}
	}

	return user, finalSession, rawT, nil
}

func (s *authenticationService) RefreshUserSession(
	ctx context.Context,
	uid UserID,
	raw RawToken,
	currentFingerprint DeviceFingerprint,
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
	session, err := user.RefreshSession(hashed, currentFingerprint, now)
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

// Access Session For User
// Authentication Service
type accessGrantor struct {
	tokenProvider IAccessTokenProvider
	policy        IAccessPolicy
	clock         IClock
}

func NewAccessGrantor(
	tokenProvider IAccessTokenProvider,
	policy IAccessPolicy,
	clock IClock,
) IAccessGrantor {
	return &accessGrantor{
		tokenProvider: tokenProvider,
		policy:        policy,
		clock:         clock,
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
	return s.tokenProvider.Generate(
		user.ID(),
		user.Email(),
		sessionID,
		user.Roles(),
		issuedAt,
		expiresAt,
		notBefore,
	)
}
