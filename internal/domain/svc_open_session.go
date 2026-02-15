package domain

import "time"

type IOpenSession interface {
	Open(
		existingSession *Session,
		activeSessions []*Session,
		userID UserID,
		identity DeviceIdentity,
		now time.Time,
	) (string, *Session, *Session, error)
}

type openSession struct {
	tokenSvc      ITokenService
	idGen         IIDGenerator
	sessionPolicy ISessionPolicy
}

func NewOpenSession(
	tokenSvc ITokenService,
	idGen IIDGenerator,
	sessionPolicy ISessionPolicy,
) IOpenSession {
	return &openSession{
		tokenSvc:      tokenSvc,
		idGen:         idGen,
		sessionPolicy: sessionPolicy,
	}
}

func (s *openSession) Open(
	existingSession *Session,
	activeSessions []*Session,
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
	if existingSession != nil {
		existingSession.UpdateLogin(hashedToken, newExpiry, now)
		return rawToken, existingSession, nil, nil
	}

	// 3. Enforce session limit
	var revokedSession *Session
	maxSessions := s.sessionPolicy.GetMaxActiveSessions()
	if len(activeSessions) >= maxSessions && len(activeSessions) > 0 {
		if err := activeSessions[0].Revoke(now); err != nil {
			return "", nil, nil, err
		}
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
