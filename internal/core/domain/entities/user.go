package entities

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"slices"
	"time"
)

type User struct {
	id           valueobjects.UserID
	email        valueobjects.Email
	passwordHash valueobjects.HashedPassword
	status       valueobjects.UserStatus
	roles        []valueobjects.Role
	createdAt    time.Time
	updatedAt    time.Time
	deletedAt    *time.Time
}

// Constructor
func NewUser(
	userID valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.HashedPassword,
	status valueobjects.UserStatus,
	roles []valueobjects.Role,
	nowUTC time.Time,
) (*User, error) {
	// Strict individual required checks
	if userID.IsEmpty() {
		return nil, derr.NewRequiredErr("user_id")
	}
	if email.Value() == "" {
		return nil, derr.NewRequiredErr("email")
	}
	if passwordHash.Value() == "" {
		return nil, derr.NewRequiredErr("password")
	}
	if string(status) == "" {
		return nil, derr.NewRequiredErr("status")
	}

	if roles == nil {
		roles = []valueobjects.Role{}
	}

	return &User{
		id:           userID,
		email:        email,
		passwordHash: passwordHash,
		status:       status,
		roles:        roles,
		createdAt:    nowUTC,
		updatedAt:    nowUTC,
	}, nil
}

func ReconstituteUser(
	id valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.HashedPassword,
	status valueobjects.UserStatus,
	roles []valueobjects.Role,
	createdAt, updatedAt time.Time,
	deletedAt *time.Time,
) (*User, error) {
	return &User{
		id:           id,
		email:        email,
		passwordHash: passwordHash,
		status:       status,
		roles:        roles,
		createdAt:    createdAt,
		updatedAt:    updatedAt,
		deletedAt:    deletedAt,
	}, nil
}

// Getters
func (e *User) ID() valueobjects.UserID {
	return e.id
}

func (e *User) Email() valueobjects.Email {
	return e.email
}

func (e *User) HashedPassword() valueobjects.HashedPassword {
	return e.passwordHash
}

func (e *User) Status() valueobjects.UserStatus {
	return e.status
}

func (e *User) Roles() []valueobjects.Role {
	return slices.Clone(e.roles) // protect internal slice
}

func (e *User) CreatedAt() time.Time {
	return e.createdAt
}

func (e *User) UpdatedAt() time.Time {
	return e.updatedAt
}

func (e *User) DeletedAt() *time.Time {
	return e.deletedAt
}

func (e *User) IsDeleted() bool {
	return e.deletedAt != nil
}

func (e *User) touch() {
	e.updatedAt = time.Now().UTC()
}

func (e *User) IsActive() bool {
	return e.Status() == valueobjects.UserActive
}

func (e *User) RolesAsStrings() []string {
	if e.roles == nil {
		return []string{}
	}

	roles := make([]string, len(e.roles))
	for i, role := range e.roles {
		roles[i] = string(role)
	}
	return roles
}

func (u *User) Activate() error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot activate a deleted user")
	}
	if u.IsActive() {
		return derr.NewRuleViolationErr("user is already active")
	}

	u.status = valueobjects.UserActive
	u.touch()
	return nil
}

func (u *User) Deactivate() error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot deactivate a deleted user")
	}
	if !u.IsActive() {
		return derr.NewRuleViolationErr("user is already inactive")
	}

	u.status = valueobjects.UserInactive
	u.touch()
	return nil
}

func (u *User) MarkDeleted() error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("user is already deleted")
	}

	now := time.Now().UTC()
	u.deletedAt = &now
	u.status = valueobjects.UserInactive
	u.touch()
	return nil
}

func (u *User) AddRole(role valueobjects.Role) error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot modify roles of a deleted user")
	}
	if slices.Contains(u.roles, role) {
		return nil
	}

	u.roles = append(u.roles, role)
	u.touch()
	return nil
}

func (u *User) RemoveRole(role valueobjects.Role) error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot modify roles of a deleted user")
	}
	if !slices.Contains(u.roles, role) {
		return nil
	}

	u.roles = slices.DeleteFunc(u.roles, func(r valueobjects.Role) bool {
		return r == role
	})
	u.touch()
	return nil
}

func (u *User) ChangeEmail(email valueobjects.Email) error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot change email of a deleted user")
	}
	if u.email.Value() == email.Value() {
		return nil
	}

	u.email = email
	u.touch()
	return nil
}

func (u *User) ChangeHashedPassword(hash valueobjects.HashedPassword) error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot change password of a deleted user")
	}

	u.passwordHash = hash
	u.touch()
	return nil
}
