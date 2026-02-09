package domain

// --- UserRegistered ---

type UserRegistered struct {
	occurredAt  Timepoint
	aggregateID string
	email       string
}

func NewUserRegistered(userID UserID, email Email, now Timepoint) UserRegistered {
	return UserRegistered{
		occurredAt:  now,
		aggregateID: userID.String(),
		email:       email.String(),
	}
}

func (e UserRegistered) EventName() string    { return "UserRegistered" }
func (e UserRegistered) OccurredAt() Timepoint { return e.occurredAt }
func (e UserRegistered) AggregateID() string   { return e.aggregateID }
func (e UserRegistered) Email() string         { return e.email }

// --- UserActivated ---

type UserActivated struct {
	occurredAt  Timepoint
	aggregateID string
}

func NewUserActivated(userID UserID, now Timepoint) UserActivated {
	return UserActivated{
		occurredAt:  now,
		aggregateID: userID.String(),
	}
}

func (e UserActivated) EventName() string    { return "UserActivated" }
func (e UserActivated) OccurredAt() Timepoint { return e.occurredAt }
func (e UserActivated) AggregateID() string   { return e.aggregateID }

// --- RoleAssigned ---

type RoleAssigned struct {
	occurredAt  Timepoint
	aggregateID string
	roleName    string
}

func NewRoleAssigned(userID UserID, role RoleName, now Timepoint) RoleAssigned {
	return RoleAssigned{
		occurredAt:  now,
		aggregateID: userID.String(),
		roleName:    role.Name(),
	}
}

func (e RoleAssigned) EventName() string    { return "RoleAssigned" }
func (e RoleAssigned) OccurredAt() Timepoint { return e.occurredAt }
func (e RoleAssigned) AggregateID() string   { return e.aggregateID }
func (e RoleAssigned) RoleName() string      { return e.roleName }

// --- EmailUpdated ---

type EmailUpdated struct {
	occurredAt  Timepoint
	aggregateID string
	oldEmail    string
	newEmail    string
}

func NewEmailUpdated(userID UserID, oldEmail Email, newEmail Email, now Timepoint) EmailUpdated {
	return EmailUpdated{
		occurredAt:  now,
		aggregateID: userID.String(),
		oldEmail:    oldEmail.String(),
		newEmail:    newEmail.String(),
	}
}

func (e EmailUpdated) EventName() string    { return "EmailUpdated" }
func (e EmailUpdated) OccurredAt() Timepoint { return e.occurredAt }
func (e EmailUpdated) AggregateID() string   { return e.aggregateID }
func (e EmailUpdated) OldEmail() string      { return e.oldEmail }
func (e EmailUpdated) NewEmail() string      { return e.newEmail }

// --- PasswordChanged ---

type PasswordChanged struct {
	occurredAt  Timepoint
	aggregateID string
}

func NewPasswordChanged(userID UserID, now Timepoint) PasswordChanged {
	return PasswordChanged{
		occurredAt:  now,
		aggregateID: userID.String(),
	}
}

func (e PasswordChanged) EventName() string    { return "PasswordChanged" }
func (e PasswordChanged) OccurredAt() Timepoint { return e.occurredAt }
func (e PasswordChanged) AggregateID() string   { return e.aggregateID }
