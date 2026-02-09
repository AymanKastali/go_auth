package domain

// ActivationToken is the Aggregate Root for the account activation context.
type ActivationToken struct {
	EventRecorder
	id          ActivationTokenID
	userID      UserID
	hashedToken ActivationTokenHash
	expiresAt   Timepoint
	isUsed      bool
}

// NewActivationToken is the factory for creating a new activation token.
func NewActivationToken(
	id ActivationTokenID,
	uid UserID,
	hash ActivationTokenHash,
	expiresAt Timepoint,
	now Timepoint,
) (*ActivationToken, error) {
	if uid.IsEmpty() {
		return nil, ErrUserIDRequired
	}
	if expiresAt.IsBefore(now) {
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
	expiresAt Timepoint,
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

func (a *ActivationToken) IsValid(now Timepoint) bool {
	return !a.IsUsed() && !a.IsExpired(now)
}

func (a *ActivationToken) IsExpired(now Timepoint) bool {
	return now.IsAfter(a.expiresAt)
}

func (a *ActivationToken) IsUsed() bool {
	return a.isUsed
}

func (a *ActivationToken) MarkAsUsed(now Timepoint) error {
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
func (a *ActivationToken) ExpiresAt() Timepoint            { return a.expiresAt }
