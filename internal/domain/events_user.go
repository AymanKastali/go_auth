package domain

import "time"

// --- UserRegistered ---

type UserRegistered struct {
	occurredAt  time.Time
	aggregateID string
	email       string
}

func NewUserRegistered(userID UserID, email Email, now time.Time) UserRegistered {
	return UserRegistered{
		occurredAt:  now,
		aggregateID: userID.String(),
		email:       email.String(),
	}
}

func (e UserRegistered) EventName() string    { return "UserRegistered" }
func (e UserRegistered) OccurredAt() time.Time { return e.occurredAt }
func (e UserRegistered) AggregateID() string   { return e.aggregateID }
func (e UserRegistered) Email() string         { return e.email }

// --- UserActivated ---

type UserActivated struct {
	occurredAt  time.Time
	aggregateID string
}

func NewUserActivated(userID UserID, now time.Time) UserActivated {
	return UserActivated{
		occurredAt:  now,
		aggregateID: userID.String(),
	}
}

func (e UserActivated) EventName() string    { return "UserActivated" }
func (e UserActivated) OccurredAt() time.Time { return e.occurredAt }
func (e UserActivated) AggregateID() string   { return e.aggregateID }

// --- UserDeactivated ---

type UserDeactivated struct {
	occurredAt  time.Time
	aggregateID string
}

func NewUserDeactivated(userID UserID, now time.Time) UserDeactivated {
	return UserDeactivated{
		occurredAt:  now,
		aggregateID: userID.String(),
	}
}

func (e UserDeactivated) EventName() string    { return "UserDeactivated" }
func (e UserDeactivated) OccurredAt() time.Time { return e.occurredAt }
func (e UserDeactivated) AggregateID() string   { return e.aggregateID }

// --- RoleAssigned ---

type RoleAssigned struct {
	occurredAt  time.Time
	aggregateID string
	roleName    string
}

func NewRoleAssigned(userID UserID, role RoleName, now time.Time) RoleAssigned {
	return RoleAssigned{
		occurredAt:  now,
		aggregateID: userID.String(),
		roleName:    role.Name(),
	}
}

func (e RoleAssigned) EventName() string    { return "RoleAssigned" }
func (e RoleAssigned) OccurredAt() time.Time { return e.occurredAt }
func (e RoleAssigned) AggregateID() string   { return e.aggregateID }
func (e RoleAssigned) RoleName() string      { return e.roleName }

// --- EmailUpdated ---

type EmailUpdated struct {
	occurredAt  time.Time
	aggregateID string
	oldEmail    string
	newEmail    string
}

func NewEmailUpdated(userID UserID, oldEmail Email, newEmail Email, now time.Time) EmailUpdated {
	return EmailUpdated{
		occurredAt:  now,
		aggregateID: userID.String(),
		oldEmail:    oldEmail.String(),
		newEmail:    newEmail.String(),
	}
}

func (e EmailUpdated) EventName() string    { return "EmailUpdated" }
func (e EmailUpdated) OccurredAt() time.Time { return e.occurredAt }
func (e EmailUpdated) AggregateID() string   { return e.aggregateID }
func (e EmailUpdated) OldEmail() string      { return e.oldEmail }
func (e EmailUpdated) NewEmail() string      { return e.newEmail }

// --- PasswordChanged ---

type PasswordChanged struct {
	occurredAt  time.Time
	aggregateID string
}

func NewPasswordChanged(userID UserID, now time.Time) PasswordChanged {
	return PasswordChanged{
		occurredAt:  now,
		aggregateID: userID.String(),
	}
}

func (e PasswordChanged) EventName() string    { return "PasswordChanged" }
func (e PasswordChanged) OccurredAt() time.Time { return e.occurredAt }
func (e PasswordChanged) AggregateID() string   { return e.aggregateID }

// --- RoleRevokedFromUser ---

type RoleRevokedFromUser struct {
	occurredAt  time.Time
	aggregateID string
	roleName    string
}

func NewRoleRevokedFromUser(userID UserID, role RoleName, now time.Time) RoleRevokedFromUser {
	return RoleRevokedFromUser{
		occurredAt:  now,
		aggregateID: userID.String(),
		roleName:    role.Name(),
	}
}

func (e RoleRevokedFromUser) EventName() string    { return "RoleRevokedFromUser" }
func (e RoleRevokedFromUser) OccurredAt() time.Time { return e.occurredAt }
func (e RoleRevokedFromUser) AggregateID() string   { return e.aggregateID }
func (e RoleRevokedFromUser) RoleName() string      { return e.roleName }

// --- UserDeleted ---

type UserDeleted struct {
	occurredAt  time.Time
	aggregateID string
}

func NewUserDeleted(userID UserID, now time.Time) UserDeleted {
	return UserDeleted{
		occurredAt:  now,
		aggregateID: userID.String(),
	}
}

func (e UserDeleted) EventName() string    { return "UserDeleted" }
func (e UserDeleted) OccurredAt() time.Time { return e.occurredAt }
func (e UserDeleted) AggregateID() string   { return e.aggregateID }
