package domain

// RecoveryToken is the Aggregate Root for the recovery context.
type RecoveryToken struct {
	EventRecorder
	id          RecoveryTokenID
	userID      UserID
	hashedToken RecoveryTokenHash
	expiresAt   Timepoint
	isUsed      bool
}

// NewRecoveryToken is the factory for creating a new recovery attempt.
func NewRecoveryToken(
	id RecoveryTokenID,
	uid UserID,
	hash RecoveryTokenHash,
	expiresAt Timepoint,
	now Timepoint,
) (*RecoveryToken, error) {
	if uid.IsEmpty() {
		return nil, ErrUserIDRequired
	}
	if expiresAt.IsBefore(now) {
		return nil, ErrSessionExpiryInPast
	}
	rt := &RecoveryToken{
		id:          id,
		userID:      uid,
		hashedToken: hash,
		expiresAt:   expiresAt,
		isUsed:      false,
	}
	rt.RecordEvent(NewPasswordResetRequested(id, uid, now))
	return rt, nil
}

// ReconstituteRecoveryToken is used by the repository to load existing tokens.
func ReconstituteRecoveryToken(
	id RecoveryTokenID,
	userID UserID,
	hashedToken RecoveryTokenHash,
	expiresAt Timepoint,
	isUsed bool,
) *RecoveryToken {
	return &RecoveryToken{
		id:          id,
		userID:      userID,
		hashedToken: hashedToken,
		expiresAt:   expiresAt,
		isUsed:      isUsed,
	}
}

// --- Business Logic ---

func (r *RecoveryToken) IsValid(now Timepoint) bool {
	return !r.IsUsed() && !r.IsExpired(now)
}

func (r *RecoveryToken) IsExpired(now Timepoint) bool {
	return now.IsAfter(r.expiresAt)
}

func (r *RecoveryToken) IsUsed() bool {
	return r.isUsed
}

func (r *RecoveryToken) MarkAsUsed(now Timepoint) error {
	if r.IsUsed() {
		return ErrRecoveryTokenRevoked
	}
	r.isUsed = true
	r.RecordEvent(NewRecoveryTokenUsed(r.id, r.userID, now))
	return nil
}

// Getters
func (r *RecoveryToken) ID() RecoveryTokenID            { return r.id }
func (r *RecoveryToken) UserID() UserID                 { return r.userID }
func (r *RecoveryToken) HashedToken() RecoveryTokenHash { return r.hashedToken }
func (r *RecoveryToken) ExpiresAt() Timepoint           { return r.expiresAt }
