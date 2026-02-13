package domain

import (
	"context"
	"time"
)

type IOpenSession interface {
	Open(
		ctx context.Context,
		userID UserID,
		identity DeviceIdentity,
		now time.Time,
	) (string, *Session, *Session, error)
}

type openSession struct {
	sessionRepo   ISessionRepository
	tokenSvc      ITokenService
	idGen         IIDGenerator
	sessionPolicy ISessionPolicy
}

func NewOpenSession(
	sessionRepo ISessionRepository,
	tokenSvc ITokenService,
	idGen IIDGenerator,
	sessionPolicy ISessionPolicy,
) IOpenSession {
	return &openSession{
		sessionRepo:   sessionRepo,
		tokenSvc:      tokenSvc,
		idGen:         idGen,
		sessionPolicy: sessionPolicy,
	}
}

func (s *openSession) Open(
	ctx context.Context,
	userID UserID,
	identity DeviceIdentity,
	now time.Time,
) (string, *Session, *Session, error) {
	// 1. Prepare Secrets
	rawToken, err := s.tokenSvc.Generate()
	if err != nil {
		return "", nil, nil, err
	}

	hashedToken, err := s.tokenSvc.HashSessionToken(rawToken)
	if err != nil {
		return "", nil, nil, err
	}

	newExpiry, err := NewSessionExpiry(now.Add(s.sessionPolicy.GetSessionLifetime()), now)
	if err != nil {
		return "", nil, nil, err
	}

	// 2. Check for existing session with same fingerprint
	existing, err := s.sessionRepo.FindActiveByUserAndFingerprint(ctx, userID, identity.Fingerprint())
	if err != nil {
		return "", nil, nil, err
	}

	if existing != nil {
		existing.UpdateLogin(hashedToken, newExpiry, now)
		return rawToken, existing, nil, nil
	}

	// 3. Enforce session limit
	var revokedSession *Session
	activeSessions, err := s.sessionRepo.FindActiveByUserID(ctx, userID)
	if err != nil {
		return "", nil, nil, err
	}

	maxSessions := s.sessionPolicy.GetMaxActiveSessions()
	if len(activeSessions) >= maxSessions && len(activeSessions) > 0 {
		_ = activeSessions[0].Revoke(now)
		revokedSession = activeSessions[0]
	}

	// 4. Create new session
	sid, err := s.idGen.GenerateSessionID()
	if err != nil {
		return "", nil, nil, err
	}

	session, err := NewSession(sid, userID, hashedToken, identity, newExpiry, now)
	if err != nil {
		return "", nil, nil, err
	}

	return rawToken, session, revokedSession, nil
}
