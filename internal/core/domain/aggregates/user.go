package aggregates

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
	roleIDs      []valueobjects.RoleID
	createdAt    time.Time
	updatedAt    time.Time
	deletedAt    *time.Time
}

func NewUser(
	userID valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.HashedPassword,
	status valueobjects.UserStatus,
	roleIDs []valueobjects.RoleID,
	now time.Time,
) (*User, error) {
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

	if roleIDs == nil {
		roleIDs = []valueobjects.RoleID{}
	}

	return &User{
		id:           userID,
		email:        email,
		passwordHash: passwordHash,
		status:       status,
		roleIDs:      slices.Clone(roleIDs),
		createdAt:    now,
		updatedAt:    now,
	}, nil
}

func ReconstituteUser(
	id valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.HashedPassword,
	status valueobjects.UserStatus,
	roleIDs []valueobjects.RoleID,
	createdAt, updatedAt time.Time,
	deletedAt *time.Time,
) (*User, error) {
	return &User{
		id:           id,
		email:        email,
		passwordHash: passwordHash,
		status:       status,
		roleIDs:      slices.Clone(roleIDs),
		createdAt:    createdAt,
		updatedAt:    updatedAt,
		deletedAt:    deletedAt,
	}, nil
}

// Getters
func (a *User) ID() valueobjects.UserID {
	return a.id
}

func (a *User) Email() valueobjects.Email {
	return a.email
}

func (a *User) HashedPassword() valueobjects.HashedPassword {
	return a.passwordHash
}

func (a *User) Status() valueobjects.UserStatus {
	return a.status
}

func (a *User) RoleIDs() []valueobjects.RoleID {
	return slices.Clone(a.roleIDs)
}

func (a *User) CreatedAt() time.Time {
	return a.createdAt
}

func (a *User) UpdatedAt() time.Time {
	return a.updatedAt
}

func (a *User) DeletedAt() *time.Time {
	return a.deletedAt
}

func (a *User) IsDeleted() bool {
	return a.deletedAt != nil
}

func (a *User) IsActive() bool {
	return a.Status() == valueobjects.UserActive
}

func (a *User) Activate(now time.Time) error {
	if a.IsDeleted() {
		return derr.NewRuleViolationErr("cannot activate a deleted user")
	}
	if a.IsActive() {
		return derr.NewRuleViolationErr("user is already active")
	}

	a.status = valueobjects.UserActive
	a.touch(now)
	return nil
}

func (a *User) Deactivate(now time.Time) error {
	if a.IsDeleted() {
		return derr.NewRuleViolationErr("cannot deactivate a deleted user")
	}
	if !a.IsActive() {
		return derr.NewRuleViolationErr("user is already inactive")
	}

	a.status = valueobjects.UserInactive
	a.touch(now)
	return nil
}

func (a *User) MarkDeleted(now time.Time) error {
	if a.IsDeleted() {
		return derr.NewRuleViolationErr("user is already deleted")
	}

	a.deletedAt = &now
	a.status = valueobjects.UserInactive
	a.touch(now)
	return nil
}

func (a *User) RemoveRole(roleID valueobjects.RoleID, now time.Time) error {
	if a.IsDeleted() {
		return derr.NewRuleViolationErr("cannot modify roles of a deleted user")
	}
	if !slices.ContainsFunc(a.roleIDs, func(r valueobjects.RoleID) bool { return r.Equal(roleID) }) {
		return nil // not assigned
	}

	a.roleIDs = slices.DeleteFunc(a.roleIDs, func(r valueobjects.RoleID) bool { return r.Equal(roleID) })
	a.touch(now)
	return nil
}

func (a *User) ChangeEmail(email valueobjects.Email, now time.Time) error {
	if a.IsDeleted() {
		return derr.NewRuleViolationErr("cannot change email of a deleted user")
	}
	if a.email.Value() == email.Value() {
		return nil
	}

	a.email = email
	a.touch(now)
	return nil
}

func (a *User) ChangeHashedPassword(hash valueobjects.HashedPassword, now time.Time) error {
	if a.IsDeleted() {
		return derr.NewRuleViolationErr("cannot change password of a deleted user")
	}

	a.passwordHash = hash
	a.touch(now)
	return nil
}

func (a *User) AddRoleID(roleID valueobjects.RoleID, now time.Time) error {
	if a.IsDeleted() {
		return derr.NewRuleViolationErr("cannot modify roles of a deleted user")
	}

	if slices.Contains(a.roleIDs, roleID) {
		return derr.NewRuleViolationErr("user already has this role")
	}

	a.roleIDs = append(a.roleIDs, roleID)
	a.touch(now)
	return nil
}

func (a *User) RemoveRoleID(roleID valueobjects.RoleID, now time.Time) error {
	if a.IsDeleted() {
		return derr.NewRuleViolationErr("cannot modify roles of a deleted user")
	}

	if !slices.ContainsFunc(a.roleIDs, func(r valueobjects.RoleID) bool { return r.Equal(roleID) }) {
		return derr.NewRuleViolationErr("user does not have this role")
	}

	if len(a.roleIDs) <= 1 {
		return derr.NewRuleViolationErr("user must have at least one role")
	}

	a.roleIDs = slices.DeleteFunc(a.roleIDs, func(r valueobjects.RoleID) bool {
		return r.Equal(roleID)
	})
	a.touch(now)
	return nil
}

func (a *User) touch(now time.Time) {
	a.updatedAt = now
}
