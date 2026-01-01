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
	var missing []string

	if userID.IsZero() {
		missing = append(missing, "id")
	}
	if email.Value() == "" {
		missing = append(missing, "email")
	}
	if passwordHash.Value() == "" {
		missing = append(missing, "password")
	}
	if status == "" {
		missing = append(missing, "state")
	}
	if roles == nil {
		roles = []valueobjects.Role{}
	}

	if len(missing) > 0 {
		return nil, domainerr.RequiredAttrsError(
			missing,
			createRefreshTokenOp,
		)
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

func (u *User) Activate() error {
	if u.IsDeleted() {
		return domainerr.OperationDeniedError(
			"deleted user cannot be activated",
			activateUserOp,
		)
	}

	if u.IsActive() {
		return domainerr.InvalidStateError(
			"user is already active",
			activateUserOp,
		)
	}

	u.status = valueobjects.UserActive
	u.touch()
	return nil
}

func (u *User) Deactivate() error {
	if u.IsDeleted() {
		return domainerr.OperationDeniedError(
			"deleted user cannot be deactivated",
			deactivateUserOp,
		)
	}

	if !u.IsActive() {
		return domainerr.InvalidStateError(
			"user is already inactive",
			deactivateUserOp,
		)
	}

	u.status = valueobjects.UserInactive
	u.touch()
	return nil
}

func (u *User) MarkDeleted() error {
	if u.IsDeleted() {
		return domainerr.InvalidStateError(
			"user is already deleted",
			deleteUserOp,
		)
	}

	now := time.Now().UTC()
	u.deletedAt = &now
	u.touch()
	return nil
}

func (u *User) AddRole(role valueobjects.Role) error {
	if u.IsDeleted() {
		return domainerr.OperationDeniedError(
			"cannot modify roles of deleted user",
			addRoleOp,
		)
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
		return domainerr.OperationDeniedError(
			"cannot modify roles of deleted user",
			removeRoleOp,
		)
	}

	if !slices.Contains(u.roles, role) {
		return nil
	}

	newRoles := make([]valueobjects.Role, 0, len(u.roles))
	for _, r := range u.roles {
		if r != role {
			newRoles = append(newRoles, r)
		}
	}

	u.roles = newRoles
	u.touch()
	return nil
}

func (u *User) ChangeEmail(email valueobjects.Email) error {
	if u.IsDeleted() {
		return domainerr.OperationDeniedError(
			"cannot change email of deleted user",
			changeEmailOp,
		)
	}

	if u.email == email {
		return nil
	}

	u.email = email
	u.touch()
	return nil
}

func (u *User) ChangeHashedPassword(hash valueobjects.HashedPassword) error {
	if u.IsDeleted() {
		return domainerr.OperationDeniedError(
			"cannot change password of deleted user",
			changePasswordOp,
		)
	}

	u.passwordHash = hash
	u.touch()
	return nil
}
