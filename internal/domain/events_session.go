package domain

import "time"

// --- SessionEstablished ---

type SessionEstablished struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewSessionEstablished(sessionID SessionID, userID UserID, now time.Time) SessionEstablished {
	return SessionEstablished{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionEstablished) EventName() string     { return "SessionEstablished" }
func (e SessionEstablished) OccurredAt() time.Time  { return e.occurredAt }
func (e SessionEstablished) AggregateID() string    { return e.aggregateID }
func (e SessionEstablished) SessionID() string      { return e.aggregateID }
func (e SessionEstablished) UserID() string         { return e.userID }

// --- SessionLoginRenewed ---

type SessionLoginRenewed struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewSessionLoginRenewed(sessionID SessionID, userID UserID, now time.Time) SessionLoginRenewed {
	return SessionLoginRenewed{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionLoginRenewed) EventName() string     { return "SessionLoginRenewed" }
func (e SessionLoginRenewed) OccurredAt() time.Time  { return e.occurredAt }
func (e SessionLoginRenewed) AggregateID() string    { return e.aggregateID }
func (e SessionLoginRenewed) SessionID() string      { return e.aggregateID }
func (e SessionLoginRenewed) UserID() string         { return e.userID }

// --- SessionRefreshed ---

type SessionRefreshed struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewSessionRefreshed(sessionID SessionID, userID UserID, now time.Time) SessionRefreshed {
	return SessionRefreshed{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionRefreshed) EventName() string     { return "SessionRefreshed" }
func (e SessionRefreshed) OccurredAt() time.Time  { return e.occurredAt }
func (e SessionRefreshed) AggregateID() string    { return e.aggregateID }
func (e SessionRefreshed) SessionID() string      { return e.aggregateID }
func (e SessionRefreshed) UserID() string         { return e.userID }

// --- SessionRevoked ---

type SessionRevoked struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewSessionRevoked(sessionID SessionID, userID UserID, now time.Time) SessionRevoked {
	return SessionRevoked{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionRevoked) EventName() string     { return "SessionRevoked" }
func (e SessionRevoked) OccurredAt() time.Time  { return e.occurredAt }
func (e SessionRevoked) AggregateID() string    { return e.aggregateID }
func (e SessionRevoked) SessionID() string      { return e.aggregateID }
func (e SessionRevoked) UserID() string         { return e.userID }

// --- SessionHijackDetected ---

type SessionHijackDetected struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewSessionHijackDetected(sessionID SessionID, userID UserID, now time.Time) SessionHijackDetected {
	return SessionHijackDetected{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionHijackDetected) EventName() string     { return "SessionHijackDetected" }
func (e SessionHijackDetected) OccurredAt() time.Time  { return e.occurredAt }
func (e SessionHijackDetected) AggregateID() string    { return e.aggregateID }
func (e SessionHijackDetected) SessionID() string      { return e.aggregateID }
func (e SessionHijackDetected) UserID() string         { return e.userID }

// --- SessionTokenRotated ---

type SessionTokenRotated struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewSessionTokenRotated(sessionID SessionID, userID UserID, now time.Time) SessionTokenRotated {
	return SessionTokenRotated{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionTokenRotated) EventName() string     { return "SessionTokenRotated" }
func (e SessionTokenRotated) OccurredAt() time.Time  { return e.occurredAt }
func (e SessionTokenRotated) AggregateID() string    { return e.aggregateID }
func (e SessionTokenRotated) SessionID() string      { return e.aggregateID }
func (e SessionTokenRotated) UserID() string         { return e.userID }

// --- SessionTokenReuseDetected ---

type SessionTokenReuseDetected struct {
	occurredAt  time.Time
	aggregateID string
	userID      string
}

func NewSessionTokenReuseDetected(sessionID SessionID, userID UserID, now time.Time) SessionTokenReuseDetected {
	return SessionTokenReuseDetected{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionTokenReuseDetected) EventName() string     { return "SessionTokenReuseDetected" }
func (e SessionTokenReuseDetected) OccurredAt() time.Time  { return e.occurredAt }
func (e SessionTokenReuseDetected) AggregateID() string    { return e.aggregateID }
func (e SessionTokenReuseDetected) SessionID() string      { return e.aggregateID }
func (e SessionTokenReuseDetected) UserID() string         { return e.userID }
