package domain

var ZeroSession = Session{}

type Session struct {
	id           SessionID
	hashedToken  HashedToken
	identity     DeviceIdentity
	expiresAt    Timepoint
	lastActiveAt Timepoint
	isRevoked    bool
}

// NewSession is the primary constructor for new domain objects.
// It enforces business invariants strictly using sentinels.
func NewSession(
	id SessionID,
	hashedToken HashedToken,
	identity DeviceIdentity,
	expiresAt Timepoint,
	now Timepoint,
) (Session, error) {
	if id.IsEmpty() {
		return ZeroSession, ErrSessionIDRequired
	}

	// Invariant: A session cannot be born expired
	if expiresAt.IsBefore(now) {
		return ZeroSession, ErrSessionExpiryInPast
	}

	return Session{
		id:           id,
		hashedToken:  hashedToken,
		identity:     identity,
		expiresAt:    expiresAt,
		lastActiveAt: now,
		isRevoked:    false,
	}, nil
}

// ReconstituteSession bypasses business rules for persistence/loading.
func ReconstituteSession(
	id SessionID,
	hashedToken HashedToken,
	identity DeviceIdentity,
	expiresAt Timepoint,
	lastActiveAt Timepoint,
	isRevoked bool,
) Session {
	return Session{
		id:           id,
		hashedToken:  hashedToken,
		identity:     identity,
		expiresAt:    expiresAt,
		lastActiveAt: lastActiveAt,
		isRevoked:    isRevoked,
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

func (s *Session) Revoke() error {
	if s.IsRevoked() {
		return ErrSessionAlreadyRevoked // Explicit sentinel from registry
	}

	s.isRevoked = true
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
func (s Session) IsRevoked() bool          { return s.isRevoked }
func (s Session) Identity() DeviceIdentity { return s.identity }
func (s Session) DisplayName() string      { return s.identity.DisplayName() }
