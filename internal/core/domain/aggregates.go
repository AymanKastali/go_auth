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

// func (a *User) AddSession(newSession Session, maxSessions int) error {
// 	if a.IsDeleted() {
// 		return NewUserDeletedError(a.id.String())
// 	}

// 	if !a.isActive {
// 		return NewUserInactiveError(a.id.String())
// 	}

// 	// Logic: If we hit the limit, remove the oldest session (FIFO)
// 	// This ensures the user is never locked out by their own sessions.
// 	if len(a.sessions) >= maxSessions {
// 		// sessions[0] is usually the oldest
// 		a.sessions = a.sessions[1:]
// 	}

//		a.sessions = append(a.sessions, newSession)
//		a.updatedAt = newSession.LastActiveAt() // Maintain Aggregate updatedAt
//		return nil
//	}
func (u *User) Login(
	newSession Session,
	maxSessions int,
) error {
	if u.IsDeleted() {
		return NewUserDeletedError(u.id.String())
	}
	if !u.isActive {
		return NewUserInactiveError(u.id.String())
	}

	// 1. Try to find an existing active session with the same device fingerprint
	for i := range u.sessions {
		// If device matches and it's not revoked
		if u.sessions[i].Identity().Fingerprint().Equal(newSession.Identity().Fingerprint()) &&
			!u.sessions[i].IsRevoked() {

			// UPDATE logic: Re-use the existing session but update its token and timestamps
			u.sessions[i].UpdateLogin(
				newSession.HashedToken(),
				newSession.ExpiresAt(),
				newSession.LastActiveAt(),
			)

			u.updatedAt = newSession.LastActiveAt()
			return nil
		}
	}

	// 2. If no matching device found, enforce the session limit (FIFO)
	if len(u.sessions) >= maxSessions {
		u.revokeOldestSession()
	}

	// 3. Add as a brand new session
	u.sessions = append(u.sessions, newSession)
	u.updatedAt = newSession.LastActiveAt()
	return nil
}

// revokeOldestSession is a private helper that removes the oldest session
// when the user logs in from too many distinct devices.
func (u *User) revokeOldestSession() {
	if len(u.sessions) == 0 {
		return
	}
	// Removes the first element (oldest) from the slice
	u.sessions = u.sessions[1:]
}

func (a *User) RefreshSession(hash HashedToken, currentFingerprint DeviceFingerprint, now Timepoint) (Session, error) {
	if a.IsDeleted() || !a.isActive {
		return ZeroSession, NewUserInactiveError(a.id.String())
	}
	for i := range a.sessions {
		if a.sessions[i].HashedToken().Equal(hash) {

			// 1. SECURITY CHECK: Ensure the hardware/browser fingerprint matches the one stored in the session
			if !a.sessions[i].ValidateFingerprint(currentFingerprint) {
				// Potential hijacking! Revoke the session immediately for safety
				_ = a.sessions[i].Revoke(now)
				a.updatedAt = now
				return ZeroSession, NewSessionFingerprintMismatchError(a.sessions[i].ID().String())
			}

			// 2. LIFECYCLE CHECK: Ensure the session hasn't expired or been revoked
			if !a.sessions[i].IsValid(now) {
				return ZeroSession, NewSessionExpiredError()
			}

			// 3. Update Activity
			a.sessions[i].UpdateActivity(now)
			a.updatedAt = now

			return a.sessions[i], nil
		}
	}
	return ZeroSession, NewSessionNotFoundError("token")
}

func (a *User) RevokeSession(sid SessionID, now Timepoint) error {
	if a.IsDeleted() {
		return NewUserDeletedError(a.id.String())
	}

	for i := range a.sessions {
		if a.sessions[i].ID().Equal(sid) {
			// 1. Tell the session entity to revoke itself
			if err := a.sessions[i].Revoke(now); err != nil {
				return err
			}

			// 2. Update the Aggregate Root's timestamp
			a.updatedAt = now
			return nil
		}
	}

	return NewSessionNotFoundError(sid.String())
}

func (u *User) HasActiveSession(sid SessionID, now Timepoint) bool {
	for _, s := range u.sessions {
		if s.ID().Equal(sid) {
			return s.IsValid(now)
		}
	}
	return false
}

func (a *User) CleanupSessions(now Timepoint) {
	a.sessions = slices.DeleteFunc(a.sessions, func(s Session) bool {
		return !s.IsValid(now)
	})
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
