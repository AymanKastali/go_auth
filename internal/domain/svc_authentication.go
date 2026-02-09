package domain

import (
	"context"
)

type IAuthenticationService interface {
	AuthenticateAndEstablishSession(
		ctx context.Context,
		user *User,
		rawPassword RawPassword,
		identity DeviceIdentity,
		now Timepoint,
	) (RawToken, *Session, error)
	RefreshSession(
		ctx context.Context,
		rawToken RawToken,
		fp DeviceFingerprint,
		now Timepoint,
	) (*User, *Session, error)
}

type authenticationService struct {
	userRepo      IUserRepository
	sessionRepo   ISessionRepository
	tokenSvc      ITokenService
	idGen         IIDGenerator
	sessionPolicy ISessionPolicy
	passwordMgr   IPasswordManager
}

func NewAuthenticationService(
	userRepo IUserRepository,
	sessionRepo ISessionRepository,
	tokenSvc ITokenService,
	idGen IIDGenerator,
	sessionPolicy ISessionPolicy,
	passwordMgr IPasswordManager,
) IAuthenticationService {
	return &authenticationService{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
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
) (RawToken, *Session, error) {
	// 1. Verify Credentials
	if !s.passwordMgr.Compare(rawPassword, user.HashedPassword()) {
		return ZeroRawToken, nil, ErrAuthenticationFailed
	}

	// 2. Check if user is active
	if !user.IsActive() {
		return ZeroRawToken, nil, ErrUserInactive
	}

	// 3. Prepare Secrets
	rawToken, err := s.tokenSvc.Generate()
	if err != nil {
		return ZeroRawToken, nil, err
	}

	hashedToken, err := s.tokenSvc.HashSessionToken(rawToken)
	if err != nil {
		return ZeroRawToken, nil, err
	}

	expiresAt := now.Add(s.sessionPolicy.GetSessionLifetime())

	// 4. Check for existing session with same fingerprint
	existing, err := s.sessionRepo.FindActiveByUserAndFingerprint(ctx, user.ID(), identity.Fingerprint())
	if err != nil {
		return ZeroRawToken, nil, err
	}

	if existing != nil {
		existing.UpdateLogin(hashedToken, expiresAt, now)
		return rawToken, existing, nil
	}

	// 5. Enforce session limit
	activeSessions, err := s.sessionRepo.FindActiveByUserID(ctx, user.ID())
	if err != nil {
		return ZeroRawToken, nil, err
	}

	maxSessions := s.sessionPolicy.GetMaxActiveSessions()
	if len(activeSessions) >= maxSessions && len(activeSessions) > 0 {
		_ = activeSessions[0].Revoke(now)
		if err := s.sessionRepo.Save(ctx, activeSessions[0]); err != nil {
			return ZeroRawToken, nil, err
		}
	}

	// 6. Create new session
	sid, err := s.idGen.GenerateSessionID()
	if err != nil {
		return ZeroRawToken, nil, err
	}

	session, err := NewSession(sid, user.ID(), hashedToken, identity, expiresAt, now)
	if err != nil {
		return ZeroRawToken, nil, err
	}

	return rawToken, session, nil
}

func (s *authenticationService) RefreshSession(
	ctx context.Context,
	rawToken RawToken,
	fp DeviceFingerprint,
	now Timepoint,
) (*User, *Session, error) {
	// 1. Hash the token for lookup
	hashed, err := s.tokenSvc.HashSessionToken(rawToken)
	if err != nil {
		return nil, nil, err
	}

	// 2. Find session by token
	session, err := s.sessionRepo.FindByToken(ctx, hashed)
	if err != nil {
		return nil, nil, err
	}
	if session == nil {
		return nil, nil, ErrSessionNotFound
	}

	// 3. Find the owning user
	user, err := s.userRepo.FindByID(ctx, session.UserID())
	if err != nil {
		return nil, nil, err
	}
	if user == nil || user.IsDeleted() || !user.IsActive() {
		return nil, nil, ErrUserInactive
	}

	// 4. Delegate to session aggregate
	if err := session.Refresh(fp, now); err != nil {
		return nil, nil, err
	}

	return user, session, nil
}
