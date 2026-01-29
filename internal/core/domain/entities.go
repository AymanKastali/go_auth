package domain

import "time"

var ZeroSession = Session{}

type Session struct {
	id           SessionID
	hashedToken  HashedToken
	identity     DeviceIdentity
	expiresAt    Timepoint
	lastActiveAt Timepoint
	revokedAt    *Timepoint
}

// NewSession is the primary constructor for new domain objects.
// It enforces business invariants strictly using sentinels.
func NewSession(
	id SessionID,
	hashedToken HashedToken,
	identity DeviceIdentity,
	expiresAt Timepoint,
	now Timepoint,
) (*Session, error) {
	if id.IsEmpty() {
		return nil, ErrSessionIDRequired // Explicit
	}

	// Invariant: A session cannot be born expired
	if expiresAt.IsBefore(now) {
		return nil, ErrSessionExpiryInPast // Explicit
	}

	return &Session{
		id:           id,
		hashedToken:  hashedToken,
		identity:     identity,
		expiresAt:    expiresAt,
		lastActiveAt: now,
		revokedAt:    nil,
	}, nil
}

// ReconstituteSession bypasses business rules for persistence/loading.
func ReconstituteSession(
	id SessionID,
	hashedToken HashedToken,
	identity DeviceIdentity,
	expiresAt Timepoint,
	lastActiveAt Timepoint,
	revokedAt *Timepoint,
) Session {
	return Session{
		id:           id,
		hashedToken:  hashedToken,
		identity:     identity,
		expiresAt:    expiresAt,
		lastActiveAt: lastActiveAt,
		revokedAt:    revokedAt,
	}
}

// --- Behavior ---

func (s Session) IsValid(now Timepoint) bool {
	if s.IsRevoked() {
		return false
	}
	return now.IsBefore(s.expiresAt)
}

func (s Session) ValidateFingerprint(currentFingerprint DeviceFingerprint) bool {
	// VO comparison is explicit and deep
	return s.identity.Fingerprint().Equal(currentFingerprint)
}

func (s *Session) UpdateLogin(newToken HashedToken, newExpiry, now Timepoint) {
	s.hashedToken = newToken
	s.expiresAt = newExpiry
	s.lastActiveAt = now
}

func (s *Session) Revoke(now Timepoint) error {
	if s.IsRevoked() {
		return ErrSessionAlreadyRevoked // Explicit sentinel from registry
	}

	s.revokedAt = &now
	return nil
}

func (s *Session) UpdateActivity(now Timepoint) {
	s.lastActiveAt = now
}

// --- Getters ---

func (s Session) ID() SessionID            { return s.id }
func (s Session) HashedToken() HashedToken { return s.hashedToken }
func (s Session) ExpiresAt() Timepoint     { return s.expiresAt }
func (s Session) LastActiveAt() Timepoint  { return s.lastActiveAt }
func (s Session) IsRevoked() bool          { return s.revokedAt != nil }
func (s Session) RevokedAt() *Timepoint    { return s.revokedAt }
func (s Session) Identity() DeviceIdentity { return s.identity }
func (s Session) DisplayName() string      { return s.identity.DisplayName() }

// RecoveryToken
type RecoveryToken struct {
	id          RecoveryTokenID
	userID      UserID
	hashedToken RecoveryTokenHash
	expiresAt   Timepoint
	createdAt   Timepoint
	usedAt      *Timepoint // If nil, the token hasn't been used yet
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
	return &RecoveryToken{
		id:          id,
		userID:      uid,
		hashedToken: hash,
		expiresAt:   expiresAt,
		usedAt:      nil,
		createdAt:   now,
	}, nil
}

// ReconstituteRecoveryToken is used by the repository to load existing tokens.
func ReconstituteRecoveryToken(
	id string,
	userID string,
	hashedToken string,
	expiresAt time.Time,
	createdAt time.Time,
	usedAt *time.Time,
) *RecoveryToken {
	var usedAtTP *Timepoint
	if usedAt != nil {
		tp := NewTimepoint(*usedAt)
		usedAtTP = &tp
	}

	return &RecoveryToken{
		id:          ReconstituteRecoveryTokenID(id),
		userID:      ReconstituteUserID(userID),
		hashedToken: ReconstituteRecoveryTokenHash(hashedToken),
		expiresAt:   NewTimepoint(expiresAt),
		createdAt:   NewTimepoint(createdAt),
		usedAt:      usedAtTP,
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
	return r.usedAt != nil
}

func (r *RecoveryToken) MarkAsUsed(now Timepoint) error {
	if r.IsUsed() {
		return ErrRecoveryTokenRevoked
	}
	r.usedAt = &now
	return nil
}

// Getters
func (r *RecoveryToken) ID() RecoveryTokenID            { return r.id }
func (r *RecoveryToken) UserID() UserID                 { return r.userID }
func (r *RecoveryToken) HashedToken() RecoveryTokenHash { return r.hashedToken }
func (r *RecoveryToken) ExpiresAt() Timepoint           { return r.expiresAt }
func (r *RecoveryToken) CreatedAt() Timepoint           { return r.createdAt }
func (r *RecoveryToken) UsedAt() *Timepoint             { return r.usedAt }
