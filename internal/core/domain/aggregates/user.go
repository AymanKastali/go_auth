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
		return nil, derr.NewValidation.RequiredUserID()
	}
	if email.IsEmpty() {
		return nil, derr.NewValidation.RequiredEmail()
	}
	if passwordHash.IsEmpty() {
		return nil, derr.NewValidation.RequiredPassword()
	}
	if status == "" {
		return nil, derr.NewValidation.RequiredStatus()
	}
	if now.IsZero() {
		return nil, derr.NewValidation.RequiredNow()
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
	if id.IsEmpty() {
		return nil, derr.NewValidation.RequiredUserID()
	}
	if createdAt.IsZero() {
		return nil, derr.NewValidation.RequiredCreatedAt()
	}

	if updatedAt.Before(createdAt) {
		return nil, derr.NewViolation.UpdatedBeforeCreated()
	}
	if deletedAt != nil && status == valueobjects.UserActive {
		return nil, derr.NewViolation.DeletedUserMustBeInactive()
	}

	if roleIDs == nil {
		roleIDs = []valueobjects.RoleID{}
	}

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

func (a *User) ensureNotDeleted() error {
	if a.IsDeleted() {
		return derr.NewViolation.UserDeleted()
	}
	return nil
}

func (a *User) ensureActive() error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if !a.IsActive() {
		return derr.NewViolation.UserAlreadyInactive()
	}
	return nil
}

func (a *User) Activate(now time.Time) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if a.IsActive() {
		return derr.NewViolation.UserAlreadyActive()
	}

	a.status = valueobjects.UserActive
	a.touch(now)
	return nil
}

func (a *User) Deactivate(now time.Time) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if !a.IsActive() {
		return derr.NewViolation.UserAlreadyInactive()
	}

	a.status = valueobjects.UserInactive
	a.touch(now)
	return nil
}

func (a *User) MarkDeleted(now time.Time) error {
	if a.IsDeleted() {
		return derr.NewViolation.UserDeleted()
	}

	a.deletedAt = &now
	a.status = valueobjects.UserInactive
	a.touch(now)
	return nil
}

func (a *User) ChangeEmail(email valueobjects.Email, now time.Time) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if a.email.Equal(email) {
		return nil
	}

	a.email = email
	a.touch(now)
	return nil
}

func (a *User) ChangeHashedPassword(hash valueobjects.HashedPassword, now time.Time) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}

	a.passwordHash = hash
	a.touch(now)
	return nil
}

func (a *User) AddRoleID(roleID valueobjects.RoleID, now time.Time) error {
	if err := a.ensureActive(); err != nil {
		return err
	}

	exists := slices.ContainsFunc(a.roleIDs, func(r valueobjects.RoleID) bool {
		return r.Equal(roleID)
	})
	if exists {
		return derr.NewViolation.RoleAlreadyAssigned()
	}

	a.roleIDs = append(a.roleIDs, roleID)
	a.touch(now)
	return nil
}

func (a *User) RemoveRoleID(roleID valueobjects.RoleID, now time.Time) error {
	if err := a.ensureActive(); err != nil {
		return err
	}

	if len(a.roleIDs) <= 1 {
		return derr.NewViolation.MinimumRoleRequired()
	}

	idx := slices.IndexFunc(a.roleIDs, func(r valueobjects.RoleID) bool {
		return r.Equal(roleID)
	})

	if idx == -1 {
		return derr.NewViolation.RoleNotFound()
	}

	a.roleIDs = slices.Delete(a.roleIDs, idx, idx+1)
	a.touch(now)
	return nil
}

func (a *User) touch(now time.Time) {
	a.updatedAt = now
}

func (a *User) ID() valueobjects.UserID                     { return a.id }
func (a *User) Email() valueobjects.Email                   { return a.email }
func (a *User) HashedPassword() valueobjects.HashedPassword { return a.passwordHash }
func (a *User) Status() valueobjects.UserStatus             { return a.status }
func (a *User) RoleIDs() []valueobjects.RoleID              { return slices.Clone(a.roleIDs) }
func (a *User) CreatedAt() time.Time                        { return a.createdAt }
func (a *User) UpdatedAt() time.Time                        { return a.updatedAt }
func (a *User) DeletedAt() *time.Time                       { return a.deletedAt }
func (a *User) IsDeleted() bool                             { return a.deletedAt != nil }
func (a *User) IsActive() bool                              { return a.status == valueobjects.UserActive }
