package entities

import (
	"errors"
	"go_auth/internal/core/domain/domainerr"
	"go_auth/internal/core/domain/valueobjects"
	"slices"
	"time"
)

const newUserOp = "User.Newuser"
const reconstituteUserOp = "User.ReconstituteUser"

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
	if userID.IsZero() {
		return nil, domainerr.NewDomainRequiredAttrError("user id", newUserOp)
	}
	if email.Value() == "" {
		return nil, domainerr.NewDomainRequiredAttrError("email", newUserOp)
	}
	if passwordHash.Value() == "" {
		return nil, domainerr.NewDomainRequiredAttrError("password", newUserOp)
	}
	if status == "" {
		return nil, domainerr.NewDomainRequiredAttrError("status", newUserOp)
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
		deletedAt:    nil,
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
	if id.IsZero() {
		return nil, domainerr.NewDomainRequiredAttrError("user id", reconstituteUserOp)
	}

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

func (e *User) Activate() error {
	if e.IsActive() {
		return errors.New("user is already active")
	}
	e.status = valueobjects.UserActive
	e.touch()
	return nil
}

func (e *User) Deactivate() error {
	if !e.IsActive() {
		return errors.New("user is already inactive")
	}
	if e.IsDeleted() {
		return errors.New("deleted user cannot be deactivated")
	}

	e.status = valueobjects.UserInactive
	e.touch()
	return nil
}

func (e *User) MarkDeleted() {
	if e.deletedAt != nil {
		return
	}

	now := time.Now().UTC()
	e.deletedAt = &now
	e.touch()
}

func (e *User) AddRole(role valueobjects.Role) {
	if slices.Contains(e.roles, role) {
		return
	}

	e.roles = append(e.roles, role)
	e.touch()
}

func (e *User) RemoveRole(role valueobjects.Role) {
	if !slices.Contains(e.roles, role) {
		return
	}

	newRoles := make([]valueobjects.Role, 0, len(e.roles))
	for _, r := range e.roles {
		if r != role {
			newRoles = append(newRoles, r)
		}
	}

	e.roles = newRoles
	e.touch()
}

func (e *User) ChangeEmail(email valueobjects.Email) error {
	if e.email == email {
		return nil
	}

	e.email = email
	e.touch()
	return nil
}
func (e *User) ChangeHashedPassword(hash valueobjects.HashedPassword) error {
	e.passwordHash = hash
	e.touch()
	return nil
}
