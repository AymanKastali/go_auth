package domain

import (
	"context"
	"time"
)

type IRefreshSession interface {
	Refresh(
		ctx context.Context,
		rawToken string,
		fp DeviceFingerprint,
		now time.Time,
	) (*User, *Session, string, error)
}

type refreshSession struct {
	userRepo      IUserRepository
	sessionRepo   ISessionRepository
	tokenSvc      ITokenService
	sessionPolicy ISessionPolicy
}

func NewRefreshSession(
	userRepo IUserRepository,
	sessionRepo ISessionRepository,
	tokenSvc ITokenService,
	sessionPolicy ISessionPolicy,
) IRefreshSession {
	return &refreshSession{
		userRepo:      userRepo,
		sessionRepo:   sessionRepo,
		tokenSvc:      tokenSvc,
		sessionPolicy: sessionPolicy,
	}
}

func (s *refreshSession) Refresh(
	ctx context.Context,
	rawToken string,
	fp DeviceFingerprint,
	now time.Time,
) (*User, *Session, string, error) {
	// 1. Hash the token for lookup
	hashed, err := s.tokenSvc.HashSessionToken(rawToken)
	if err != nil {
		return nil, nil, "", err
	}

	// 2. Find session by current token
	session, err := s.sessionRepo.FindByToken(ctx, hashed)
	if err != nil {
		return nil, nil, "", err
	}

	// 3. If not found by current token, check for reuse
	if session == nil {
		session, err = s.sessionRepo.FindByPreviousToken(ctx, hashed)
		if err != nil {
			return nil, nil, "", err
		}
		if session != nil && !session.IsRevoked() {
			_ = session.RevokeForTokenReuse(now)
			return nil, session, "", ErrSessionTokenReuse
		}
		return nil, nil, "", ErrSessionNotFound
	}

	// 4. Find the owning user
	user, err := s.userRepo.FindByID(ctx, session.UserID())
	if err != nil {
		return nil, nil, "", err
	}
	if user == nil || user.IsDeleted() || !user.IsActive() {
		return nil, nil, "", ErrUserInactive
	}

	// 5. Generate new token for rotation
	newRawToken, err := s.tokenSvc.Generate()
	if err != nil {
		return nil, nil, "", err
	}

	newHashedToken, err := s.tokenSvc.HashSessionToken(newRawToken)
	if err != nil {
		return nil, nil, "", err
	}

	// 6. Construct new expiry
	newExpiry, err := NewSessionExpiry(now.Add(s.sessionPolicy.GetSessionLifetime()), now)
	if err != nil {
		return nil, nil, "", err
	}

	// 7. Delegate to session aggregate (rotation + sliding expiry)
	if err := session.Refresh(newHashedToken, fp, newExpiry, now); err != nil {
		return nil, nil, "", err
	}

	return user, session, newRawToken, nil
}
