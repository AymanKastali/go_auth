package domain

import "time"

// --- ActivationRequested ---

type ActivationRequested struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewActivationRequested(tokenID ActivationTokenID, userID UserID, now time.Time) ActivationRequested {
	return ActivationRequested{
		occurredAt:  now,
		aggregateID: tokenID.String(),
		userID:      userID.String(),
	}
}

func (e ActivationRequested) EventName() string    { return "ActivationRequested" }
func (e ActivationRequested) OccurredAt() time.Time { return e.occurredAt }
func (e ActivationRequested) AggregateID() string   { return e.aggregateID }
func (e ActivationRequested) UserID() string        { return e.userID }

// --- ActivationTokenUsed ---

type ActivationTokenUsed struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewActivationTokenUsed(tokenID ActivationTokenID, userID UserID, now time.Time) ActivationTokenUsed {
	return ActivationTokenUsed{
		occurredAt:  now,
		aggregateID: tokenID.String(),
		userID:      userID.String(),
	}
}

func (e ActivationTokenUsed) EventName() string    { return "ActivationTokenUsed" }
func (e ActivationTokenUsed) OccurredAt() time.Time { return e.occurredAt }
func (e ActivationTokenUsed) AggregateID() string   { return e.aggregateID }
func (e ActivationTokenUsed) UserID() string        { return e.userID }
