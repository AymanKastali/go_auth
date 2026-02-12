package domain

import "time"

// Session is the Aggregate Root for session lifecycle management.
type Session struct {
	EventRecorder
	id           SessionID
	userID       UserID
	hashedToken  HashedToken
	identity     DeviceIdentity
	expiresAt    time.Time
	lastActiveAt time.Time
	isRevoked    bool
}

// NewSession enforces business invariants during initial creation.
func NewSession(
	id SessionID,
	userID UserID,
	hashedToken HashedToken,
	identity DeviceIdentity,
	expiresAt time.Time,
	now time.Time,
) (*Session, error) {
	if id.IsEmpty() {
		return nil, ErrSessionIDRequired
	}
	if userID.IsEmpty() {
		return nil, ErrSessionUserIDRequired
	}
	if expiresAt.Before(now) {
		return nil, ErrSessionExpiryInPast
	}

	s := &Session{
		id:           id,
		userID:       userID,
		hashedToken:  hashedToken,
		identity:     identity,
		expiresAt:    expiresAt,
		lastActiveAt: now,
		isRevoked:    false,
	}
	s.RecordEvent(NewSessionEstablished(id, userID, now))
	return s, nil
}

// ReconstituteSession bypasses business rules for persistence loading.
func ReconstituteSession(
	id SessionID,
	userID UserID,
	hashedToken HashedToken,
	identity DeviceIdentity,
	expiresAt time.Time,
	lastActiveAt time.Time,
	isRevoked bool,
) *Session {
	return &Session{
		id:           id,
		userID:       userID,
		hashedToken:  hashedToken,
		identity:     identity,
		expiresAt:    expiresAt,
		lastActiveAt: lastActiveAt,
		isRevoked:    isRevoked,
	}
}

// --- Behavior ---

func (s *Session) IsValid(now time.Time) bool {
	if s.IsRevoked() {
		return false
	}
	return now.Before(s.expiresAt)
}

func (s *Session) ValidateFingerprint(currentFingerprint DeviceFingerprint) bool {
	return s.identity.Fingerprint().Equal(currentFingerprint)
}

func (s *Session) UpdateLogin(newToken HashedToken, newExpiry, now time.Time) {
	s.hashedToken = newToken
	s.expiresAt = newExpiry
	s.lastActiveAt = now
	s.RecordEvent(NewSessionEstablished(s.id, s.userID, now))
}

func (s *Session) Revoke(now time.Time) error {
	if s.IsRevoked() {
		return ErrSessionAlreadyRevoked
	}

	s.isRevoked = true
	s.RecordEvent(NewSessionRevoked(s.id, s.userID, now))
	return nil
}

func (s *Session) Refresh(currentFP DeviceFingerprint, now time.Time) error {
	if !s.ValidateFingerprint(currentFP) {
		s.isRevoked = true
		s.RecordEvent(NewSessionHijackDetected(s.id, s.userID, now))
		return ErrSessionFingerprintMiss
	}

	if !s.IsValid(now) {
		return ErrSessionExpired
	}

	s.lastActiveAt = now
	s.RecordEvent(NewSessionRefreshed(s.id, s.userID, now))
	return nil
}

func (s *Session) UpdateActivity(now time.Time) {
	s.lastActiveAt = now
}

// --- Getters ---

func (s *Session) ID() SessionID            { return s.id }
func (s *Session) UserID() UserID           { return s.userID }
func (s *Session) HashedToken() HashedToken { return s.hashedToken }
func (s *Session) ExpiresAt() time.Time     { return s.expiresAt }
func (s *Session) LastActiveAt() time.Time  { return s.lastActiveAt }
func (s *Session) IsRevoked() bool          { return s.isRevoked }
func (s *Session) Identity() DeviceIdentity { return s.identity }
func (s *Session) DisplayName() string      { return s.identity.DisplayName() }
