package domain

import (
	"context"
)

type userAccountManager struct {
	userRepo       IUserRepository
	recoveryRepo   IRecoveryTokenRepository
	tokenSvc       ITokenService
	passwordMgr    IPasswordManager
	idGen          IIDGenerator
	recoveryPolicy IRecoveryPolicy
}

func NewUserAccountManager(
	userRepo IUserRepository,
	recoveryRepo IRecoveryTokenRepository,
	tokenSvc ITokenService,
	passwordMgr IPasswordManager,
	idGen IIDGenerator,
	recoveryPolicy IRecoveryPolicy,
) IUserAccountManager {
	return &userAccountManager{
		userRepo:       userRepo,
		recoveryRepo:   recoveryRepo,
		tokenSvc:       tokenSvc,
		passwordMgr:    passwordMgr,
		idGen:          idGen,
		recoveryPolicy: recoveryPolicy,
	}
}

func (manager *userAccountManager) InitiatePasswordReset(
	ctx context.Context,
	user *User,
	now Timepoint,
) (RawToken, *RecoveryToken, error) {
	// 1. Invariant Checks
	if !user.IsActive() {
		return ZeroRawToken, nil, ErrUserInactive
	}

	// 2. Technical Logic
	rawToken, err := manager.tokenSvc.Generate()
	if err != nil {
		return ZeroRawToken, nil, err
	}

	hashedToken, err := manager.tokenSvc.HashRecoveryToken(rawToken)
	if err != nil {
		return ZeroRawToken, nil, err
	}

	// 3. Policy Application
	expirationTime := now.Add(manager.recoveryPolicy.GetRecoveryTokenLifetime())

	// 4. Aggregate Construction (The Service acts as a Factory coordinator)
	// We get the ID from the repository (identity generation is a repo responsibility)
	id, err := manager.idGen.GenerateRecoveryTokenID()
	if err != nil {
		return ZeroRawToken, nil, err
	}

	recoveryToken, err := NewRecoveryToken(
		id,
		user.ID(),
		hashedToken,
		expirationTime,
		now,
	)
	if err != nil {
		return ZeroRawToken, nil, err
	}

	return rawToken, recoveryToken, nil
}

func (m *userAccountManager) ChangePassword(
	ctx context.Context,
	user *User,
	oldPass RawPassword,
	newPass RawPassword,
	now Timepoint,
) error {
	if !m.passwordMgr.Compare(oldPass, user.HashedPassword()) {
		return ErrAuthenticationFailed
	}

	newHash, err := m.passwordMgr.ValidateAndHashNewPassword(newPass)
	if err != nil {
		return err
	}

	return user.UpdatePassword(newHash, now)
}

func (m *userAccountManager) ResetPasswordByToken(
	ctx context.Context,
	token RawToken,
	newPassword RawPassword,
	now Timepoint,
) error {
	// 1. Resolve Token Hash
	hashed, err := m.tokenSvc.HashRecoveryToken(token)
	if err != nil {
		return err
	}

	// 2. Fetch & Validate Recovery Aggregate
	recovery, err := m.recoveryRepo.FindByHash(ctx, hashed)
	if err != nil {
		return err
	}
	if recovery == nil || !recovery.IsValid(now) {
		return ErrRecoveryTokenInvalid
	}

	// 3. Fetch User Aggregate
	user, err := m.userRepo.FindByID(ctx, recovery.UserID())
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// 4. Cross-Aggregate Invariant: Token Ownership
	if !recovery.UserID().Equal(user.ID()) {
		return ErrInvalidRecoveryAttempt
	}

	// 5. Technical Process: Validation & Hashing combined
	// We delegate the "How" of the new secret to the Manager
	newHash, err := m.passwordMgr.ValidateAndHashNewPassword(newPassword)
	if err != nil {
		return err
	}

	// 6. Execute State Transitions
	if err := user.UpdatePassword(newHash, now); err != nil {
		return err
	}
	if err := recovery.MarkAsUsed(now); err != nil {
		return err
	}

	// 7. Atomic Persistence
	if err := m.userRepo.Save(ctx, user); err != nil {
		return err
	}
	return m.recoveryRepo.Save(ctx, recovery)
}

type accessManager struct {
	userRepo     IUserRepository
	accessSvc    IAccessService
	accessPolicy IAccessPolicy
}

func NewAccessManager(
	userRepo IUserRepository,
	accessSvc IAccessService,
	accessPolicy IAccessPolicy,
) IAccessManager {
	return &accessManager{
		userRepo:     userRepo,
		accessSvc:    accessSvc,
		accessPolicy: accessPolicy,
	}
}

func (m *accessManager) GrantImmediateAccess(
	user *User,
	sid SessionID,
	now Timepoint,
) (AccessToken, Timepoint, error) {
	issuedAt := now
	notBefore := now

	ttl := m.accessPolicy.GetAccessLifetime()
	expiresAt := issuedAt.Add(ttl)

	return m.accessSvc.Issue(
		user.ID(),
		user.Email(),
		sid,
		user.Roles(),
		issuedAt,
		expiresAt,
		notBefore,
	)
}

func (m *accessManager) VerifyAccess(ctx context.Context, token AccessToken, now Timepoint) (*User, SessionID, error) {
	// 1. Technical Domain Step: Cryptographic validation (The "Dumb" Service)
	identity, err := m.accessSvc.Validate(token)
	if err != nil {
		return nil, ZeroSessionID, err
	}

	// 2. Identity Resolution: Fetch the Aggregate Root
	user, err := m.userRepo.FindByID(ctx, identity.UserID())
	if err != nil || user == nil {
		return nil, ZeroSessionID, ErrUserNotFound
	}

	// 3. Aggregate Invariant Check: Session Integrity
	// This is where the User Aggregate checks if the SID is revoked or expired
	sid := identity.SessionID()
	if err := user.ValidateIntegrity(sid, now); err != nil {
		return nil, ZeroSessionID, err
	}

	return user, sid, nil
}

type authenticationService struct {
	userRepo      IUserRepository
	tokenSvc      ITokenService
	idGen         IIDGenerator
	sessionPolicy ISessionPolicy
	passwordMgr   IPasswordManager
}

func NewAuthenticationService(
	userRepo IUserRepository,
	tokenSvc ITokenService,
	idGen IIDGenerator,
	sessionPolicy ISessionPolicy,
	passwordMgr IPasswordManager,
) IAuthenticationService {
	return &authenticationService{
		userRepo:      userRepo,
		tokenSvc:      tokenSvc,
		idGen:         idGen,
		sessionPolicy: sessionPolicy,
		passwordMgr:   passwordMgr,
	}
}

func (s *authenticationService) AuthenticateAndEstablishSession(
	ctx context.Context,
	user *User,
	rawPassword RawPassword,
	identity DeviceIdentity,
	now Timepoint,
) (RawToken, Session, error) {
	// 1. Verify Credentials using internal dependency
	if !s.passwordMgr.Compare(rawPassword, user.HashedPassword()) {
		return ZeroRawToken, ZeroSession, ErrAuthenticationFailed
	}

	// 2. Resolve Session ID
	sid, found := user.FindActiveSessionByFingerprint(identity.Fingerprint())
	if !found {
		generatedSid, err := s.idGen.GenerateSessionID()
		if err != nil {
			return ZeroRawToken, ZeroSession, err
		}
		sid = generatedSid
	}

	// 3. Prepare Secrets
	rawToken, err := s.tokenSvc.Generate()
	if err != nil {
		return ZeroRawToken, ZeroSession, err
	}

	hashedToken, err := s.tokenSvc.HashSessionToken(rawToken)
	if err != nil {
		return ZeroRawToken, ZeroSession, err
	}

	// 4. Invariants and Policy Math
	expiresAt := now.Add(s.sessionPolicy.GetSessionLifetime())

	session, err := NewSession(sid, hashedToken, identity, expiresAt, now)
	if err != nil {
		return ZeroRawToken, ZeroSession, err
	}

	// 5. Delegate to Aggregate Root
	if err := user.EstablishSession(session, s.sessionPolicy.GetMaxActiveSessions()); err != nil {
		return ZeroRawToken, ZeroSession, err
	}

	return rawToken, session, nil
}

func (s *authenticationService) RefreshSession(
	ctx context.Context,
	rawToken RawToken,
	fp DeviceFingerprint,
	now Timepoint,
) (*User, Session, error) {
	// 1. Technical Domain Rule: Tokens are stored as hashes
	hashed, err := s.tokenSvc.HashSessionToken(rawToken)
	if err != nil {
		return nil, ZeroSession, err
	}

	// 2. Identity Resolution: Find the owner via the repository
	user, err := s.userRepo.FindBySessionToken(ctx, hashed)
	if err != nil {
		return nil, ZeroSession, err
	}
	if user == nil {
		return nil, ZeroSession, ErrSessionNotFound
	}

	// 3. Delegation to Aggregate: The Aggregate Root enforces the business rules
	session, err := user.RefreshSession(hashed, fp, now)
	if err != nil {
		return nil, ZeroSession, err
	}

	return user, session, nil
}

type passwordManager struct {
	svc    IPasswordService
	policy IPasswordPolicy
}

func NewPasswordManager(
	svc IPasswordService,
	policy IPasswordPolicy,
) *passwordManager {
	return &passwordManager{
		svc:    svc,
		policy: policy,
	}
}

func (m *passwordManager) ValidateAndHashNewPassword(raw RawPassword) (HashedPassword, error) {
	if err := m.policy.Validate(raw); err != nil {
		return ZeroHashedPassword, err
	}
	return m.svc.Hash(raw)
}

func (m *passwordManager) Compare(raw RawPassword, hashed HashedPassword) bool {
	return m.svc.Compare(raw, hashed)
}

type registrationService struct {
	userRepo       IUserRepository
	registerPolicy IRegisterPolicy
}

func NewRegistrationService(
	userRepo IUserRepository,
	registerPolicy IRegisterPolicy,
) *registrationService {
	return &registrationService{
		userRepo:       userRepo,
		registerPolicy: registerPolicy,
	}
}

func (s *registrationService) RegisterNewMember(
	ctx context.Context,
	id UserID,
	email Email,
	pwd HashedPassword,
	now Timepoint,
) (*User, error) {
	if err := s.registerPolicy.Validate(email); err != nil {
		return nil, err
	}

	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserEmailTaken
	}

	user, err := NewUser(id, email, pwd, now)
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

func (s *registrationService) RegisterNewSuperAdmin(
	ctx context.Context,
	id UserID,
	email Email,
	pwd HashedPassword,
	now Timepoint,
) (*User, error) {
	if err := s.registerPolicy.Validate(email); err != nil {
		return nil, err
	}

	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserEmailTaken
	}

	user, err := NewUser(id, email, pwd, now)
	if err != nil {
		return nil, err
	}

	if err := user.AssignRole(RoleAdmin, now); err != nil {
		return nil, err
	}

	if err := user.Activate(now); err != nil {
		return nil, err
	}

	return user, nil
}
