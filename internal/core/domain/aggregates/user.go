package aggregates

import (
	"go_auth/internal/core/domain/derr"
	"go_auth/internal/core/domain/valueobjects"
	"slices"
)

type User struct {
	id           valueobjects.UserID
	email        valueobjects.Email
	passwordHash valueobjects.HashedPassword
	status       valueobjects.UserStatus
	roleIDs      []valueobjects.RoleID
	createdAt    valueobjects.Timepoint
	updatedAt    valueobjects.Timepoint
	deletedAt    *valueobjects.Timepoint
}

func NewUser(
	userID valueobjects.UserID,
	email valueobjects.Email,
	passwordHash valueobjects.HashedPassword,
	status valueobjects.UserStatus,
	roleIDs []valueobjects.RoleID,
	now valueobjects.Timepoint,
) (*User, error) {
	if userID.IsEmpty() {
		return nil, derr.NewErrUserIDRequired()
	}
	if email.IsEmpty() {
		return nil, derr.NewErrEmailRequired()
	}
	if passwordHash.IsEmpty() {
		return nil, derr.NewErrUserPasswordRequired()
	}
	if status == "" {
		return nil, derr.NewErrUserStatusRequired()
	}
	if now.IsZero() {
		return nil, derr.NewErrTimepointRequired()
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
	createdAt, updatedAt valueobjects.Timepoint,
	deletedAt *valueobjects.Timepoint,
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
		return derr.NewErrUserDeleted(a.ID().Value())
	}
	return nil
}

func (a *User) ensureActive() error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if !a.IsActive() {
		return derr.NewErrUserAlreadyInactive(a.ID().Value())
	}
	return nil
}

func (a *User) Activate(currentTime valueobjects.Timepoint) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if a.IsActive() {
		return derr.NewErrUserAlreadyActive(a.ID().Value())
	}

	a.status = valueobjects.UserActive
	a.touch(currentTime)
	return nil
}

func (a *User) Deactivate(currentTime valueobjects.Timepoint) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}
	if !a.IsActive() {
		return derr.NewErrUserAlreadyInactive(a.ID().Value())
	}

	a.status = valueobjects.UserInactive
	a.touch(currentTime)
	return nil
}

func (a *User) MarkDeleted(currentTime valueobjects.Timepoint) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}

	a.deletedAt = &currentTime
	a.status = valueobjects.UserInactive
	a.touch(currentTime)
	return nil
}

func (a *User) ChangeEmail(email valueobjects.Email, currentTime valueobjects.Timepoint) error {
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

func (a *User) ChangeHashedPassword(hash valueobjects.HashedPassword, currentTime valueobjects.Timepoint) error {
	if err := a.ensureNotDeleted(); err != nil {
		return err
	}

	a.passwordHash = hash
	a.touch(currentTime)
	return nil
}

func (a *User) AddRoleID(roleID valueobjects.RoleID, currentTime valueobjects.Timepoint) error {
	if err := a.ensureActive(); err != nil {
		return err
	}

	exists := slices.ContainsFunc(a.roleIDs, func(r valueobjects.RoleID) bool {
		return r.Equal(roleID)
	})
	if exists {
		return derr.NewErrRoleAlreadyAssignedToUser(a.ID().Value(), roleID.Value())
	}

	a.roleIDs = append(a.roleIDs, roleID)
	a.touch(currentTime)
	return nil
}

func (a *User) RemoveRoleID(roleID valueobjects.RoleID, currentTime valueobjects.Timepoint) error {
	if err := a.ensureActive(); err != nil {
		return err
	}

	if len(a.roleIDs) <= 1 {
		return derr.NewErrMinimumRolesRequired(a.ID().Value())
	}

	idx := slices.IndexFunc(a.roleIDs, func(r valueobjects.RoleID) bool {
		return r.Equal(roleID)
	})

	a.roleIDs = slices.Delete(a.roleIDs, idx, idx+1)
	a.touch(currentTime)
	return nil
}

func (a *User) touch(currentTime valueobjects.Timepoint) {
	a.updatedAt = currentTime
}

func (a *User) ID() valueobjects.UserID                     { return a.id }
func (a *User) Email() valueobjects.Email                   { return a.email }
func (a *User) HashedPassword() valueobjects.HashedPassword { return a.passwordHash }
func (a *User) Status() valueobjects.UserStatus             { return a.status }
func (a *User) RoleIDs() []valueobjects.RoleID              { return slices.Clone(a.roleIDs) }
func (a *User) CreatedAt() valueobjects.Timepoint           { return a.createdAt }
func (a *User) UpdatedAt() valueobjects.Timepoint           { return a.updatedAt }
func (a *User) DeletedAt() *valueobjects.Timepoint          { return a.deletedAt }
func (a *User) IsDeleted() bool                             { return a.deletedAt != nil }
func (a *User) IsActive() bool                              { return a.status == valueobjects.UserActive }
