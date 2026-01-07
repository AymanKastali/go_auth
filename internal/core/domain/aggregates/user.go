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

// Constructor
func NewUser(
	userID valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.HashedPassword,
	status valueobjects.UserStatus,
	roleIDs []valueobjects.RoleID,
	nowUTC time.Time,
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
		createdAt:    nowUTC,
		updatedAt:    nowUTC,
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
func (u *User) ID() valueobjects.UserID {
	return u.id
}

func (u *User) Email() valueobjects.Email {
	return u.email
}

func (u *User) HashedPassword() valueobjects.HashedPassword {
	return u.passwordHash
}

func (u *User) Status() valueobjects.UserStatus {
	return u.status
}

func (u *User) RoleIDs() []valueobjects.RoleID {
	return slices.Clone(u.roleIDs)
}

func (u *User) CreatedAt() time.Time {
	return u.createdAt
}

func (u *User) UpdatedAt() time.Time {
	return u.updatedAt
}

func (u *User) DeletedAt() *time.Time {
	return u.deletedAt
}

func (u *User) IsDeleted() bool {
	return u.deletedAt != nil
}

func (u *User) IsActive() bool {
	return u.Status() == valueobjects.UserActive
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

func (u *User) AddRole(roleID valueobjects.RoleID) error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot modify roles of a deleted user")
	}
	if roleID.IsEmpty() {
		return derr.NewRequiredErr("role_id")
	}
	if slices.ContainsFunc(u.roleIDs, func(r valueobjects.RoleID) bool { return r.Equal(roleID) }) {
		return nil // already assigned
	}

	u.roleIDs = append(u.roleIDs, roleID)
	u.touch()
	return nil
}

func (u *User) RemoveRole(roleID valueobjects.RoleID) error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot modify roles of a deleted user")
	}
	if !slices.ContainsFunc(u.roleIDs, func(r valueobjects.RoleID) bool { return r.Equal(roleID) }) {
		return nil // not assigned
	}

	u.roleIDs = slices.DeleteFunc(u.roleIDs, func(r valueobjects.RoleID) bool { return r.Equal(roleID) })
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

// Add a RoleID
func (u *User) AddRoleID(roleID valueobjects.RoleID) error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot modify roles of a deleted user")
	}

	if slices.Contains(u.roleIDs, roleID) {
		return derr.NewRuleViolationErr("user already has this role")
	}

	u.roleIDs = append(u.roleIDs, roleID)
	u.touch()
	return nil
}

// Remove a RoleID with minimum 1 role check
func (u *User) RemoveRoleID(roleID valueobjects.RoleID) error {
	if u.IsDeleted() {
		return derr.NewRuleViolationErr("cannot modify roles of a deleted user")
	}

	if !slices.ContainsFunc(u.roleIDs, func(r valueobjects.RoleID) bool { return r.Equal(roleID) }) {
		return derr.NewRuleViolationErr("user does not have this role")
	}

	if len(u.roleIDs) <= 1 {
		return derr.NewRuleViolationErr("user must have at least one role")
	}

	u.roleIDs = slices.DeleteFunc(u.roleIDs, func(r valueobjects.RoleID) bool {
		return r.Equal(roleID)
	})
	u.touch()
	return nil
}

func (u *User) touch() {
	u.updatedAt = time.Now().UTC()
}
