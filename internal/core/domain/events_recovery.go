package domain

// --- PasswordResetRequested ---

type PasswordResetRequested struct {
	occurredAt  Timepoint
	aggregateID string
	userID      string
}

func NewPasswordResetRequested(tokenID RecoveryTokenID, userID UserID, now Timepoint) PasswordResetRequested {
	return PasswordResetRequested{
		occurredAt:  now,
		aggregateID: tokenID.String(),
		userID:      userID.String(),
	}
}

func (e PasswordResetRequested) EventName() string    { return "PasswordResetRequested" }
func (e PasswordResetRequested) OccurredAt() Timepoint { return e.occurredAt }
func (e PasswordResetRequested) AggregateID() string   { return e.aggregateID }
func (e PasswordResetRequested) UserID() string        { return e.userID }

// --- RecoveryTokenUsed ---

type RecoveryTokenUsed struct {
	occurredAt  Timepoint
	aggregateID string
	userID      string
}

func NewRecoveryTokenUsed(tokenID RecoveryTokenID, userID UserID, now Timepoint) RecoveryTokenUsed {
	return RecoveryTokenUsed{
		occurredAt:  now,
		aggregateID: tokenID.String(),
		userID:      userID.String(),
	}
}

func (e RecoveryTokenUsed) EventName() string    { return "RecoveryTokenUsed" }
func (e RecoveryTokenUsed) OccurredAt() Timepoint { return e.occurredAt }
func (e RecoveryTokenUsed) AggregateID() string   { return e.aggregateID }
func (e RecoveryTokenUsed) UserID() string        { return e.userID }
