package domain

var ZeroSession = Session{}

type Session struct {
	id           SessionID
	hashedToken  HashedToken
	identity     DeviceIdentity
	expiresAt    Timepoint
	lastActiveAt Timepoint
	revokedAt    *Timepoint
}

// Session Constructors
func NewSession(
	id SessionID,
	hashedToken HashedToken,
	identity DeviceIdentity,
	expiresAt Timepoint,
	now Timepoint,
) (*Session, error) {
	if id.IsEmpty() {
		return nil, NewRequiredAttributeError(EntitySession, "id")
	}
	if expiresAt.IsBefore(now) {
		return nil, NewExpirationInPastError()
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

// Session Behavior
func (s Session) IsValid(now Timepoint) bool {
	if s.IsRevoked() {
		return false
	}
	return now.IsBefore(s.expiresAt)
}

func (s Session) ValidateFingerprint(currentFingerprint DeviceFingerprint) bool {
	return s.identity.Fingerprint() == currentFingerprint
}

func (s *Session) Revoke(now Timepoint) error {
	if s.IsRevoked() {
		return NewTokenAlreadyRevokedError(s.id.String())
	}

	s.revokedAt = &now
	return nil
}

func (s *Session) UpdateActivity(now Timepoint) { s.lastActiveAt = now }

// Session Getters
func (s Session) ID() SessionID            { return s.id }
func (s Session) HashedToken() HashedToken { return s.hashedToken }
func (s Session) ExpiresAt() Timepoint     { return s.expiresAt }
func (s Session) LastActiveAt() Timepoint  { return s.lastActiveAt }
func (s Session) IsRevoked() bool          { return s.revokedAt != nil }
func (s Session) RevokedAt() *Timepoint    { return s.revokedAt }
func (s Session) Identity() DeviceIdentity { return s.identity }
func (s Session) DisplayName() string      { return s.identity.DisplayName() }
