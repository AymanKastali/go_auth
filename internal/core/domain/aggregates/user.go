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
	currentTime time.Time,
) (*User, error) {
	if userID.IsEmpty() {
		return nil, derr.ErrUserIDRequired()
	}
	if email.IsEmpty() {
		return nil, derr.ErrEmailRequired()
	}
	if passwordHash.IsEmpty() {
		return nil, derr.ErrPasswordRequired()
	}
	if status == "" {
		return nil, derr.ErrStatusRequired()
	}
	if currentTime.IsZero() {
		return nil, derr.ErrCurrentTimeRequired()
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
		createdAt:    currentTime,
		updatedAt:    currentTime,
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
) *User {
	return &User{
		id:           id,
		email:        email,
		passwordHash: passwordHash,
		status:       status,
		roleIDs:      slices.Clone(roleIDs),
		createdAt:    createdAt,
		updatedAt:    updatedAt,
		deletedAt:    deletedAt,
	}
}

func (a *User) ensureNotDeleted() error {
	if a.IsDeleted() {
		return derr.ErrUserDeleted(a.id.Value())
	}
	return nil
}

func (a *User) ensureActive() error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if !a.IsActive() {
		return derr.ErrUserAlreadyInactive(a.id.Value())
	}
	return nil
}

func (a *User) Activate(currentTime time.Time) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if a.IsActive() {
		return derr.ErrUserAlreadyActive(a.id.Value())
	}

	a.status = valueobjects.UserActive
	a.touch(currentTime)
	return nil
}

func (a *User) Deactivate(currentTime time.Time) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if !a.IsActive() {
		return derr.ErrUserAlreadyInactive(a.id.Value())
	}

	a.status = valueobjects.UserInactive
	a.touch(currentTime)
	return nil
}

func (a *User) MarkDeleted(currentTime time.Time) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}

	a.deletedAt = &currentTime
	a.status = valueobjects.UserInactive
	a.touch(currentTime)
	return nil
}

func (a *User) ChangeEmail(email valueobjects.Email, currentTime time.Time) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if a.email.Equal(email) {
		return nil
	}

	a.email = email
	a.touch(currentTime)
	return nil
}

func (a *User) ChangeHashedPassword(hash valueobjects.HashedPassword, currentTime time.Time) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}

	a.passwordHash = hash
	a.touch(currentTime)
	return nil
}

func (a *User) AddRoleID(roleID valueobjects.RoleID, currentTime time.Time) error {
	if err := a.ensureActive(); err != nil {
		return err
	}

	exists := slices.ContainsFunc(a.roleIDs, func(r valueobjects.RoleID) bool {
		return r.Equal(roleID)
	})
	if exists {
		return derr.ErrRoleAlreadyAssigned(roleID.Value())
	}

	a.roleIDs = append(a.roleIDs, roleID)
	a.touch(currentTime)
	return nil
}

func (a *User) RemoveRoleID(roleID valueobjects.RoleID, currentTime time.Time) error {
	if err := a.ensureActive(); err != nil {
		return err
	}

	if len(a.roleIDs) <= 1 {
		return derr.ErrMinimumRolesRequirement(1)
	}

	idx := slices.IndexFunc(a.roleIDs, func(r valueobjects.RoleID) bool {
		return r.Equal(roleID)
	})

	if idx == -1 {
		return derr.ErrRoleNotAssigned(roleID.Value())
	}

	a.roleIDs = slices.Delete(a.roleIDs, idx, idx+1)
	a.touch(currentTime)
	return nil
}

func (a *User) touch(currentTime time.Time) {
	a.updatedAt = currentTime
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
