package domain

// --- SessionEstablished ---

type SessionEstablished struct {
	occurredAt  Timepoint
	aggregateID string
	userID      string
}

func NewSessionEstablished(sessionID SessionID, userID UserID, now Timepoint) SessionEstablished {
	return SessionEstablished{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionEstablished) EventName() string     { return "SessionEstablished" }
func (e SessionEstablished) OccurredAt() Timepoint  { return e.occurredAt }
func (e SessionEstablished) AggregateID() string    { return e.aggregateID }
func (e SessionEstablished) SessionID() string      { return e.aggregateID }
func (e SessionEstablished) UserID() string         { return e.userID }

// --- SessionRefreshed ---

type SessionRefreshed struct {
	occurredAt  Timepoint
	aggregateID string
	userID      string
}

func NewSessionRefreshed(sessionID SessionID, userID UserID, now Timepoint) SessionRefreshed {
	return SessionRefreshed{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionRefreshed) EventName() string     { return "SessionRefreshed" }
func (e SessionRefreshed) OccurredAt() Timepoint  { return e.occurredAt }
func (e SessionRefreshed) AggregateID() string    { return e.aggregateID }
func (e SessionRefreshed) SessionID() string      { return e.aggregateID }
func (e SessionRefreshed) UserID() string         { return e.userID }

// --- SessionRevoked ---

type SessionRevoked struct {
	occurredAt  Timepoint
	aggregateID string
	userID      string
}

func NewSessionRevoked(sessionID SessionID, userID UserID, now Timepoint) SessionRevoked {
	return SessionRevoked{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionRevoked) EventName() string     { return "SessionRevoked" }
func (e SessionRevoked) OccurredAt() Timepoint  { return e.occurredAt }
func (e SessionRevoked) AggregateID() string    { return e.aggregateID }
func (e SessionRevoked) SessionID() string      { return e.aggregateID }
func (e SessionRevoked) UserID() string         { return e.userID }

// --- SessionHijackDetected ---

type SessionHijackDetected struct {
	occurredAt  Timepoint
	aggregateID string
	userID      string
}

func NewSessionHijackDetected(sessionID SessionID, userID UserID, now Timepoint) SessionHijackDetected {
	return SessionHijackDetected{
		occurredAt:  now,
		aggregateID: sessionID.String(),
		userID:      userID.String(),
	}
}

func (e SessionHijackDetected) EventName() string     { return "SessionHijackDetected" }
func (e SessionHijackDetected) OccurredAt() Timepoint  { return e.occurredAt }
func (e SessionHijackDetected) AggregateID() string    { return e.aggregateID }
func (e SessionHijackDetected) SessionID() string      { return e.aggregateID }
func (e SessionHijackDetected) UserID() string         { return e.userID }
