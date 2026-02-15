package domain

import "time"

// DomainEvent is the marker interface for all domain events.
type DomainEvent interface {
	EventName() string
	OccurredAt() time.Time
	AggregateID() string
}

// EventRecorder is an embeddable struct for aggregate-level event collection.
// Aggregates embed this to record domain events as invariants change.
type EventRecorder struct {
	events []DomainEvent
}

// RecordEvent appends a domain event to the recorder.
func (r *EventRecorder) RecordEvent(event DomainEvent) {
	r.events = append(r.events, event)
}

// CollectEvents returns all recorded events and clears the internal list
// to prevent double-dispatching.
func (r *EventRecorder) CollectEvents() []DomainEvent {
	events := r.events
	r.events = nil
	return events
}
