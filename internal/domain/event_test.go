package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEventRecorder_RecordAndCollect(t *testing.T) {
	var rec EventRecorder

	e1 := NewUserRegistered(validUserID(), validEmail(), testNow)
	e2 := NewUserActivated(validUserID(), testNow)
	rec.RecordEvent(e1)
	rec.RecordEvent(e2)

	events := rec.CollectEvents()
	assert.Len(t, events, 2)
	assert.Equal(t, "UserRegistered", events[0].EventName())
	assert.Equal(t, "UserActivated", events[1].EventName())

	// Second call returns nil (cleared)
	assert.Nil(t, rec.CollectEvents())
}

func TestEventRecorder_EmptyCollect(t *testing.T) {
	var rec EventRecorder
	assert.Nil(t, rec.CollectEvents())
}

func TestDomainEvent_Fields(t *testing.T) {
	uid := validUserID()
	e := NewUserRegistered(uid, validEmail(), testNow)
	assert.Equal(t, "UserRegistered", e.EventName())
	assert.Equal(t, uid.String(), e.AggregateID())
	assert.True(t, e.OccurredAt().Equal(testNow))
}
