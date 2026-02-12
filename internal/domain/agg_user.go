package domain

import (
	"slices"
	"time"
)

// User is the Aggregate Root for the Identity context.
type User struct {
	EventRecorder
	id           UserID
	email        Email
	passwordHash HashedPassword
	isActive     bool
	roles        []RoleName
	isDeleted    bool
	registeredAt time.Time
}

// NewUser enforces business invariants during initial creation.
func NewUser(
	userID UserID,
	email Email,
	passwordHash HashedPassword,
	registeredAt time.Time,
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
		isActive:     true,
		roles:        []RoleName{},
		isDeleted:    false,
		registeredAt: registeredAt,
	}
	u.RecordEvent(NewUserRegistered(userID, email, registeredAt))
	return u, nil
}

// ReconstituteUser is for Repository use only.
func ReconstituteUser(
	id UserID,
	email Email,
	passwordHash HashedPassword,
	isActive bool,
	roles []RoleName,
	isDeleted bool,
	registeredAt time.Time,
) *User {
	return &User{
		id:           id,
		email:        email,
		passwordHash: passwordHash,
		isActive:     isActive,
		roles:        slices.Clone(roles),
		isDeleted:    isDeleted,
		registeredAt: registeredAt,
	}
}

// --- Business Behavior ---

func (u *User) Activate(now time.Time) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}
	if u.isActive {
		return nil // Idempotent
	}

	u.isActive = true
	u.RecordEvent(NewUserActivated(u.id, now))
	return nil
}

func (u *User) Deactivate(now time.Time) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}
	if !u.isActive {
		return nil // Idempotent
	}

	u.isActive = false
	u.RecordEvent(NewUserDeactivated(u.id, now))
	return nil
}

func (u *User) AssignRole(role RoleName, now time.Time) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}

	for _, r := range u.roles {
		if r.Equal(role) {
			return nil
		}
	}

	u.roles = append(u.roles, role)
	u.RecordEvent(NewRoleAssigned(u.id, role, now))
	return nil
}

func (u *User) RemoveRole(role RoleName, now time.Time) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}

	for i, r := range u.roles {
		if r.Equal(role) {
			u.roles = append(u.roles[:i], u.roles[i+1:]...)
			u.RecordEvent(NewRoleRevokedFromUser(u.id, role, now))
			return nil
		}
	}

	return ErrRoleNotAssigned
}

func (u *User) MarkDeleted(now time.Time) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}

	u.isDeleted = true
	u.isActive = false
	u.RecordEvent(NewUserDeleted(u.id, now))
	return nil
}

func (u *User) UpdateEmail(newEmail Email, now time.Time) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}

	if u.email.Equal(newEmail) {
		return nil
	}

	oldEmail := u.email
	u.email = newEmail
	u.RecordEvent(NewEmailUpdated(u.id, oldEmail, newEmail, now))
	return nil
}

func (u *User) UpdatePassword(newHash HashedPassword, now time.Time) error {
	if u.IsDeleted() {
		return ErrUserDeleted
	}
	if !u.isActive {
		return ErrUserInactive
	}

	u.passwordHash = newHash
	u.RecordEvent(NewPasswordChanged(u.id, now))
	return nil
}

// --- Getters ---

func (u *User) ID() UserID                     { return u.id }
func (u *User) Email() Email                   { return u.email }
func (u *User) HashedPassword() HashedPassword { return u.passwordHash }
func (u *User) Roles() []RoleName               { return slices.Clone(u.roles) }
func (u *User) IsDeleted() bool                { return u.isDeleted }
func (u *User) IsActive() bool                 { return u.isActive }
func (u *User) RegisteredAt() time.Time        { return u.registeredAt }
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
