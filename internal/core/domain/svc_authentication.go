package domain

import (
	"context"
)

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
