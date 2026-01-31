package domain

import (
	"slices"
)

// User is the Aggregate Root for the Identity context.
type User struct {
	EventRecorder
	id           UserID
	email        Email
	passwordHash HashedPassword
	isActive     bool
	roles        []Role
	sessions     []Session
	createdAt    Timepoint
	updatedAt    Timepoint
	deletedAt    *Timepoint
}

// NewUser enforces business invariants during initial creation.
func NewUser(
	userID UserID,
	email Email,
	passwordHash HashedPassword,
	now Timepoint,
) (*User, error) {
	if userID.IsEmpty() {
		return nil, ErrUserIDRequired
	}
	if email.IsEmpty() {
		return nil, ErrUserEmailRequired
	}
	if passwordHash.IsEmpty() {
		return nil, ErrUserPasswordRequired
	}

	u := &User{
		id:           userID,
		email:        email,
		passwordHash: passwordHash,
		isActive:     false, // Users start inactive (awaiting activation)
		roles:        []Role{},
		sessions:     []Session{},
		createdAt:    now,
		updatedAt:    now,
		deletedAt:    nil,
	}
	u.RecordEvent(NewUserRegistered(userID, email, now))
	return u, nil
}

// ReconstituteUser is for Repository use only.
func ReconstituteUser(
	id UserID,
	email Email,
	passwordHash HashedPassword,
	isActive bool,
	roles []Role,
	sessions []Session,
	createdAt, updatedAt Timepoint,
	deletedAt *Timepoint,
) *User {
	return &User{
		id:           id,
		email:        email,
		passwordHash: passwordHash,
		isActive:     isActive,
		roles:        slices.Clone(roles),
		sessions:     slices.Clone(sessions),
		createdAt:    createdAt,
		updatedAt:    updatedAt,
		deletedAt:    deletedAt,
	}
}

// --- Business Behavior ---

func (u *User) Activate(now Timepoint) error {
	if u.IsDeleted() {
		return ErrUserDeleted // Or ErrUserDeleted if you have it
	}
	if u.isActive {
		return nil // Idempotent
	}

	u.isActive = true
	u.updatedAt = now
	u.RecordEvent(NewUserActivated(u.id, now))
	return nil
}

func (u *User) AssignRole(role Role, now Timepoint) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}

	for _, r := range u.roles {
		if r.Equal(role) {
			return nil
		}
	}

	u.roles = append(u.roles, role)
	u.updatedAt = now
	u.RecordEvent(NewRoleAssigned(u.id, role, now))
	return nil
}

func (u *User) EstablishSession(candidate Session, maxSessions int) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}
	if !u.isActive {
		return ErrUserInactive
	}

	now := candidate.LastActiveAt()

	// 1. Logic: Update existing session if fingerprint matches
	for i := range u.sessions {
		// IMPORTANT: Use &u.sessions[i] to get a pointer to the ACTUAL element in the slice
		s := &u.sessions[i]

		if s.Identity().Fingerprint().Equal(candidate.Identity().Fingerprint()) && !s.IsRevoked() {
			// Internal mutation is safe because the Aggregate Root (User) is doing it
			s.UpdateLogin(candidate.HashedToken(), candidate.ExpiresAt(), now)
			u.updatedAt = now
			u.RecordEvent(NewSessionEstablished(u.id, s.ID(), now))
			return nil
		}
	}

	// 2. Logic: Enforce session limit invariant
	if len(u.sessions) >= maxSessions {
		u.revokeOldestSession(now)
	}

	// 3. Logic: Add the new session value
	u.sessions = append(u.sessions, candidate)
	u.updatedAt = now
	u.RecordEvent(NewSessionEstablished(u.id, candidate.ID(), now))
	return nil
}

func (u *User) RefreshSession(hash HashedToken, currentFingerprint DeviceFingerprint, now Timepoint) (Session, error) {
	if u.IsDeleted() || !u.isActive {
		return ZeroSession, ErrUserInactive
	}

	for i := range u.sessions {
		s := &u.sessions[i] // Pointer to mutate the slice element
		if s.HashedToken().Equal(hash) {
			// Invariant: Detect hijacking
			if !s.ValidateFingerprint(currentFingerprint) {
				_ = s.Revoke(now)
				u.updatedAt = now
				u.RecordEvent(NewSessionHijackDetected(u.id, s.ID(), now))
				return ZeroSession, ErrSessionFingerprintMiss
			}

			// Invariant: Check expiry
			if !s.IsValid(now) {
				return ZeroSession, ErrSessionExpired
			}

			// State Update
			s.UpdateActivity(now)
			u.updatedAt = now
			u.RecordEvent(NewSessionRefreshed(u.id, s.ID(), now))
			return *s, nil // Return the updated session value
		}
	}
	return ZeroSession, ErrTokenInvalid
}

func (u *User) RevokeSession(sid SessionID, now Timepoint) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}

	for i := range u.sessions {
		s := &u.sessions[i]
		if s.ID().Equal(sid) {
			if s.IsRevoked() {
				return ErrSessionAlreadyRevoked
			}
			if err := s.Revoke(now); err != nil {
				return err
			}
			u.updatedAt = now
			u.RecordEvent(NewSessionRevoked(u.id, sid, now))
			return nil
		}
	}
	return ErrSessionIDRequired
}

func (u *User) ValidateIntegrity(sid SessionID, now Timepoint) error {
	if u.IsDeleted() || !u.isActive {
		return ErrUserInactive
	}

	for _, s := range u.sessions {
		if s.ID().Equal(sid) {
			if s.IsRevoked() {
				return ErrSessionAlreadyRevoked
			}
			if !s.IsValid(now) {
				return ErrSessionExpired
			}
			return nil
		}
	}
	return ErrSessionIDRequired
}

// --- Private Helpers ---

func (u *User) revokeOldestSession(now Timepoint) {
	for i := range u.sessions {
		if !u.sessions[i].IsRevoked() {
			_ = u.sessions[i].Revoke(now)
			u.RecordEvent(NewSessionRevoked(u.id, u.sessions[i].ID(), now))
			break
		}
	}
}

func (u *User) UpdateEmail(newEmail Email, now Timepoint) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}

	// If the email is the same, do nothing (idempotent)
	if u.email.Equal(newEmail) {
		return nil
	}

	oldEmail := u.email
	u.email = newEmail
	u.updatedAt = now
	u.RecordEvent(NewEmailUpdated(u.id, oldEmail, newEmail, now))

	// Note: In many systems, changing an email would also set u.isActive = false
	// to trigger a new email verification flow.
	return nil
}

func (u *User) UpdatePassword(newHash HashedPassword, now Timepoint) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}
	if !u.isActive {
		return ErrUserInactive
	}

	u.passwordHash = newHash
	u.updatedAt = now

	// Side effect: Security invariant - Kill all sessions on password change
	for i := range u.sessions {
		if !u.sessions[i].IsRevoked() {
			_ = u.sessions[i].Revoke(now)
			u.RecordEvent(NewSessionRevoked(u.id, u.sessions[i].ID(), now))
		}
	}

	u.RecordEvent(NewPasswordChanged(u.id, now))
	return nil
}

func (u *User) FindActiveSessionByFingerprint(fp DeviceFingerprint) (SessionID, bool) {
	for _, s := range u.sessions {
		if !s.IsRevoked() && s.Identity().Fingerprint().Equal(fp) {
			return s.ID(), true
		}
	}
	return ZeroSessionID, false
}

// --- Getters ---

func (u *User) ID() UserID                     { return u.id }
func (u *User) Email() Email                   { return u.email }
func (u *User) HashedPassword() HashedPassword { return u.passwordHash }
func (u *User) Roles() []Role                  { return slices.Clone(u.roles) }
func (u *User) Sessions() []Session            { return slices.Clone(u.sessions) }
func (u *User) IsDeleted() bool                { return u.deletedAt != nil }
func (u *User) IsActive() bool                 { return u.isActive }
func (u *User) CreatedAt() Timepoint           { return u.createdAt }
func (u *User) UpdatedAt() Timepoint           { return u.updatedAt }
func (u *User) DeletedAt() *Timepoint          { return u.deletedAt }
func (u *User) RoleNames() []string {
	if len(u.roles) == 0 {
		return []string{}
	}

	names := make([]string, len(u.roles))
	for i, r := range u.roles {
		names[i] = r.Name()
	}
	return names
}
