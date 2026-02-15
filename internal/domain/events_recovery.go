package domain

import "time"

// --- PasswordResetRequested ---

type PasswordResetRequested struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewPasswordResetRequested(tokenID RecoveryTokenID, userID UserID, now time.Time) PasswordResetRequested {
	return PasswordResetRequested{
		occurredAt:  now,
		aggregateID: tokenID.String(),
		userID:      userID.String(),
	}
}

func (e PasswordResetRequested) EventName() string    { return "PasswordResetRequested" }
func (e PasswordResetRequested) OccurredAt() time.Time { return e.occurredAt }
func (e PasswordResetRequested) AggregateID() string   { return e.aggregateID }
func (e PasswordResetRequested) UserID() string        { return e.userID }

// --- RecoveryTokenUsed ---

type RecoveryTokenUsed struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewRecoveryTokenUsed(tokenID RecoveryTokenID, userID UserID, now time.Time) RecoveryTokenUsed {
	return RecoveryTokenUsed{
		occurredAt:  now,
		aggregateID: tokenID.String(),
		userID:      userID.String(),
	}
}

func (e RecoveryTokenUsed) EventName() string    { return "RecoveryTokenUsed" }
func (e RecoveryTokenUsed) OccurredAt() time.Time { return e.occurredAt }
func (e RecoveryTokenUsed) AggregateID() string   { return e.aggregateID }
func (e RecoveryTokenUsed) UserID() string        { return e.userID }
