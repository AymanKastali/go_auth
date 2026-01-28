package domain

import (
	"slices"
)

// User
type User struct {
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

// User Constructors
func NewUser(
	userID UserID,
	email Email,
	passwordHash HashedPassword,
	now Timepoint,
) (*User, error) {
	if userID.IsEmpty() {
		return nil, NewRequiredAttributeError(EntityUser, "id")
	}
	if email.IsEmpty() {
		return nil, NewRequiredAttributeError(EntityUser, "email")
	}
	if passwordHash.IsEmpty() {
		return nil, NewRequiredAttributeError(EntityUser, "passwordHash")
	}
	if now.IsZero() {
		return nil, NewRequiredAttributeError(EntityUser, "now")
	}

	return &User{
		id:           userID,
		email:        email,
		passwordHash: passwordHash,
		isActive:     false,
		roles:        []Role{},
		sessions:     []Session{},
		createdAt:    now,
		updatedAt:    now,
		deletedAt:    nil,
	}, nil
}

func ReconstituteUser(
	id UserID,
	email Email,
	passwordHash HashedPassword,
	IsActive bool,
	roles []Role,
	sessions []Session,
	createdAt, updatedAt Timepoint,
	deletedAt *Timepoint,
) *User {
	return &User{
		id:           id,
		email:        email,
		passwordHash: passwordHash,
		isActive:     IsActive,
		roles:        slices.Clone(roles),
		sessions:     slices.Clone(sessions),
		createdAt:    createdAt,
		updatedAt:    updatedAt,
		deletedAt:    deletedAt,
	}
}

// User Behavior
func (a *User) Activate(now Timepoint) error {
	if a.IsDeleted() {
		return NewUserDeletedError(a.ID().String())
	}

	if a.isActive {
		return NewUserAlreadyActiveError(a.ID().String())
	}

	a.isActive = true
	a.updatedAt = now
	return nil
}

func (u *User) AssignRole(role Role, now Timepoint) error {
	// 1. Guard against modifications to deleted entities
	if u.IsDeleted() {
		return NewUserDeletedError(u.id.String())
	}

	// 2. Prevent logical duplicates
	for _, r := range u.roles {
		if r.Equal(role) {
			return nil // Already assigned, no action needed
		}
	}

	// 3. Apply state change
	u.roles = append(u.roles, role)

	// 4. Update the aggregate's version/timestamp
	u.updatedAt = now

	return nil
}

func (u *User) HasRole(name string) bool {
	for _, r := range u.roles {
		if r.Name() == name {
			return true
		}
	}
	return false
}

func (u *User) EstablishSession(candidate Session, maxSessions int) error {
	if u.IsDeleted() {
		return NewUserDeletedError(u.id.String())
	}
	if !u.isActive {
		return NewUserInactiveError(u.id.String())
	}

	now := candidate.LastActiveAt()

	for i := range u.sessions {
		s := &u.sessions[i]
		if s.Identity().Fingerprint().Equal(candidate.Identity().Fingerprint()) && !s.IsRevoked() {
			s.UpdateLogin(
				candidate.HashedToken(),
				candidate.ExpiresAt(),
				now,
			)
			u.updatedAt = now
			return nil
		}
	}

	// Now the call matches the func(now Timepoint) signature
	if len(u.sessions) >= maxSessions {
		u.revokeOldestSession(now)
	}

	u.sessions = append(u.sessions, candidate)
	u.updatedAt = now
	return nil
}

// revokeOldestSession is a private helper that removes the oldest session
// when the user logs in from too many distinct devices.
func (u *User) revokeOldestSession(now Timepoint) {
	if len(u.sessions) == 0 {
		return
	}

	// Step A: Find the first active (non-revoked) session and revoke it.
	// Usually, u.sessions[0] is the oldest if you always append.
	for i := range u.sessions {
		if !u.sessions[i].IsRevoked() {
			_ = u.sessions[i].Revoke(now)
			break // We only need to revoke one to make room
		}
	}

	// Step B: Optional - If you want to keep the slice clean of revoked sessions
	// to respect the maxSessions count strictly in memory:
	// u.sessions = slices.DeleteFunc(u.sessions, func(s Session) bool { return s.IsRevoked() })
	//
	// Note: Most GORM setups prefer you keep the session in the slice so it
	// can issue the UPDATE command for that specific ID.
}

func (a *User) RefreshSession(hash HashedToken, currentFingerprint DeviceFingerprint, now Timepoint) (Session, error) {
	if a.IsDeleted() || !a.isActive {
		return ZeroSession, NewUserInactiveError(a.id.String())
	}

	for i := range a.sessions {
		s := &a.sessions[i] // Pointer to ensure update persists in the aggregate
		if s.HashedToken().Equal(hash) {

			if !s.ValidateFingerprint(currentFingerprint) {
				_ = s.Revoke(now)
				a.updatedAt = now
				return ZeroSession, NewSessionFingerprintMismatchError(s.ID().String())
			}

			if !s.IsValid(now) {
				return ZeroSession, NewSessionExpiredError()
			}

			s.UpdateActivity(now)
			a.updatedAt = now

			return *s, nil // Return the updated value
		}
	}
	return ZeroSession, NewSessionNotFoundError("token")
}

func (a *User) RevokeSession(sid SessionID, now Timepoint) error {
	if a.IsDeleted() {
		return NewUserDeletedError(a.id.String())
	}

	for i := range a.sessions {
		s := &a.sessions[i] // Must use pointer to modify state
		if s.ID().Equal(sid) {

			// STRICT RULE: If it's already revoked, throw an error
			if s.IsRevoked() {
				return NewTokenAlreadyRevokedError(sid.String())
			}

			if err := s.Revoke(now); err != nil {
				return err
			}

			a.updatedAt = now
			return nil
		}
	}

	return NewSessionNotFoundError(sid.String())
}

func (a *User) CleanupSessions(now Timepoint) {
	a.sessions = slices.DeleteFunc(a.sessions, func(s Session) bool {
		return !s.IsValid(now)
	})
}

func (u *User) ValidateIntegrity(sid SessionID, now Timepoint) error {
	if u.IsDeleted() {
		return NewUserDeletedError(u.id.String())
	}
	if !u.isActive {
		return NewUserInactiveError(u.id.String())
	}

	// Explicitly find the session to provide a better error message
	for _, s := range u.sessions {
		if s.ID().Equal(sid) {
			if s.IsRevoked() {
				// Return 409 Conflict style error
				return NewTokenAlreadyRevokedError(sid.String())
			}
			if !s.IsValid(now) {
				return NewSessionExpiredError()
			}
			return nil
		}
	}

	// If not found in the user's list at all
	return NewSessionInvalidError(sid.String())
}

// User Getters
func (a *User) ID() UserID                     { return a.id }
func (a *User) Email() Email                   { return a.email }
func (a *User) HashedPassword() HashedPassword { return a.passwordHash }
func (a *User) Roles() []Role                  { return slices.Clone(a.roles) }
func (a *User) Sessions() []Session            { return slices.Clone(a.sessions) }
func (a *User) CreatedAt() Timepoint           { return a.createdAt }
func (a *User) UpdatedAt() Timepoint           { return a.updatedAt }
func (a *User) DeletedAt() *Timepoint          { return a.deletedAt }
func (a *User) IsDeleted() bool                { return a.deletedAt != nil }
func (a *User) IsActive() bool                 { return a.isActive }
func (u *User) RoleNames() []string {
	names := make([]string, len(u.roles))
	for i, r := range u.roles {
		names[i] = r.Name()
	}
	return names
}
