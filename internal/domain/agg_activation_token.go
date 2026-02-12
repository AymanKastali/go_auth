package domain

import "time"

// ActivationToken is the Aggregate Root for the account activation context.
type ActivationToken struct {
	EventRecorder
	id          ActivationTokenID
	userID      UserID
	hashedToken ActivationTokenHash
	expiresAt   time.Time
	isUsed      bool
}

// NewActivationToken is the factory for creating a new activation token.
func NewActivationToken(
	id ActivationTokenID,
	uid UserID,
	hash ActivationTokenHash,
	expiresAt time.Time,
	now time.Time,
) (*ActivationToken, error) {
	if uid.IsEmpty() {
		return nil, ErrUserIDRequired
	}
	if expiresAt.Before(now) {
		return nil, ErrSessionExpiryInPast
	}
	at := &ActivationToken{
		id:          id,
		userID:      uid,
		hashedToken: hash,
		expiresAt:   expiresAt,
		isUsed:      false,
	}
	at.RecordEvent(NewActivationRequested(id, uid, now))
	return at, nil
}

// ReconstituteActivationToken is used by the repository to load existing tokens.
func ReconstituteActivationToken(
	id ActivationTokenID,
	userID UserID,
	hashedToken ActivationTokenHash,
	expiresAt time.Time,
	isUsed bool,
) *ActivationToken {
	return &ActivationToken{
		id:          id,
		userID:      userID,
		hashedToken: hashedToken,
		expiresAt:   expiresAt,
		isUsed:      isUsed,
	}
}

// --- Business Logic ---

func (a *ActivationToken) IsValid(now time.Time) bool {
	return !a.IsUsed() && !a.IsExpired(now)
}

func (a *ActivationToken) IsExpired(now time.Time) bool {
	return now.After(a.expiresAt)
}

func (a *ActivationToken) IsUsed() bool {
	return a.isUsed
}

func (a *ActivationToken) MarkAsUsed(now time.Time) error {
	if a.IsUsed() {
		return ErrActivationTokenAlreadyUsed
	}
	a.isUsed = true
	a.RecordEvent(NewActivationTokenUsed(a.id, a.userID, now))
	return nil
}

// Getters
func (a *ActivationToken) ID() ActivationTokenID          { return a.id }
func (a *ActivationToken) UserID() UserID                  { return a.userID }
func (a *ActivationToken) HashedToken() ActivationTokenHash { return a.hashedToken }
func (a *ActivationToken) ExpiresAt() time.Time            { return a.expiresAt }
