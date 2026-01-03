package entities

import (
	"go_auth/internal/core/domain/domainerr"
	"go_auth/internal/core/domain/valueobjects"
	"slices"
	"time"
)

const (
	newUserOp          = "User.Create"
	reconstituteUserOp = "User.Reconstitute"
	activateUserOp     = "User.Activate"
	deactivateUserOp   = "User.Deactivate"
	deleteUserOp       = "User.Delete"
	changeEmailOp      = "User.ChangeEmail"
	changePasswordOp   = "User.ChangePassword"
	addRoleOp          = "User.AddRole"
	removeRoleOp       = "User.RemoveRole"
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
		return nil, domainerr.NewRequired("user_id")
	}
	if email.Value() == "" {
		return nil, domainerr.NewRequired("email")
	}
	if passwordHash.Value() == "" {
		return nil, domainerr.NewRequired("password")
	}
	if string(status) == "" {
		return nil, domainerr.NewRequired("status")
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
		return domainerr.NewRuleViolation("cannot activate a deleted user")
	}
	if u.IsActive() {
		return domainerr.NewRuleViolation("user is already active")
	}

	u.status = valueobjects.UserActive
	u.touch()
	return nil
}

func (u *User) Deactivate() error {
	if u.IsDeleted() {
		return domainerr.NewRuleViolation("cannot deactivate a deleted user")
	}
	if !u.IsActive() {
		return domainerr.NewRuleViolation("user is already inactive")
	}

	u.status = valueobjects.UserInactive
	u.touch()
	return nil
}

func (u *User) MarkDeleted() error {
	if u.IsDeleted() {
		return domainerr.NewRuleViolation("user is already deleted")
	}

	now := time.Now().UTC()
	u.deletedAt = &now
	u.status = valueobjects.UserInactive
	u.touch()
	return nil
}

func (u *User) AddRole(role valueobjects.Role) error {
	if u.IsDeleted() {
		return domainerr.NewRuleViolation("cannot modify roles of a deleted user")
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
		return domainerr.NewRuleViolation("cannot modify roles of a deleted user")
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
		return domainerr.NewRuleViolation("cannot change email of a deleted user")
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
		return domainerr.NewRuleViolation("cannot change password of a deleted user")
	}

	u.passwordHash = hash
	u.touch()
	return nil
}
