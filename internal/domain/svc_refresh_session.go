package domain

import "time"

type IRefreshSession interface {
	Refresh(
		session *Session,
		foundByPreviousToken bool,
		fp DeviceFingerprint,
		now time.Time,
	) (string, error)
}

type refreshSession struct {
	tokenSvc      ITokenService
	sessionPolicy ISessionPolicy
}

func NewRefreshSession(
	tokenSvc ITokenService,
	sessionPolicy ISessionPolicy,
) IRefreshSession {
	return &refreshSession{
		tokenSvc:      tokenSvc,
		sessionPolicy: sessionPolicy,
	}
}

func (s *refreshSession) Refresh(
	session *Session,
	foundByPreviousToken bool,
	fp DeviceFingerprint,
	now time.Time,
) (string, error) {
	// Token reuse detection
	if foundByPreviousToken {
		if !session.IsRevoked() {
			if err := session.RevokeForTokenReuse(now); err != nil {
				return "", err
			}
			return "", ErrSessionTokenReuse
		}
		return "", ErrSessionNotFound
	}

	// Generate new token for rotation
	newRawToken, err := s.tokenSvc.Generate()
	if err != nil {
		return "", err
	}

	newHashedToken, err := s.tokenSvc.HashSessionToken(newRawToken)
	if err != nil {
		return "", err
	}

	// Construct new expiry
	newExpiry, err := NewSessionExpiry(now.Add(s.sessionPolicy.GetSessionLifetime()), now)
	if err != nil {
		return "", err
	}

	// Delegate to session aggregate (rotation + sliding expiry)
	if err := session.Refresh(newHashedToken, fp, newExpiry, now); err != nil {
		return "", err
	}

	return newRawToken, nil
}
