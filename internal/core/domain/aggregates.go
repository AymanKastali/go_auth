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

func (a *User) AddSession(newSession Session, maxSessions int) error {
	if a.IsDeleted() {
		return NewUserDeletedError(a.id.String())
	}

	if !a.isActive {
		return NewUserInactiveError(a.id.String())
	}

	// Logic: If we hit the limit, remove the oldest session (FIFO)
	// This ensures the user is never locked out by their own sessions.
	if len(a.sessions) >= maxSessions {
		// sessions[0] is usually the oldest
		a.sessions = a.sessions[1:]
	}

	a.sessions = append(a.sessions, newSession)
	a.updatedAt = newSession.LastActiveAt() // Maintain Aggregate updatedAt
	return nil
}

func (a *User) RefreshSession(hash HashedToken, fp DeviceFingerprint, now Timepoint) (Session, error) {
	for i := range a.sessions {
		if a.sessions[i].HashedToken().Equal(hash) {
			// ... existing validation logic ...

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
