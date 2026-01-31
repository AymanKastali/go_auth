package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewTimepoint(t *testing.T) {
	t.Run("utc_normalization", func(t *testing.T) {
		loc, _ := time.LoadLocation("America/New_York")
		eastern := time.Date(2025, 6, 15, 12, 0, 0, 0, loc)
		tp := NewTimepoint(eastern)
		assert.Equal(t, time.UTC, tp.Time().Location())
		assert.Equal(t, eastern.UTC(), tp.Time())
	})
}

func TestTimepoint_IsBefore(t *testing.T) {
	assert.True(t, testPast.IsBefore(testNow))
	assert.False(t, testNow.IsBefore(testPast))
	assert.False(t, testNow.IsBefore(testNow))
}

func TestTimepoint_IsAfter(t *testing.T) {
	assert.True(t, testNow.IsAfter(testPast))
	assert.False(t, testPast.IsAfter(testNow))
}

func TestTimepoint_Add(t *testing.T) {
	result := testNow.Add(24 * time.Hour)
	assert.True(t, result.Equal(testFuture))
}

func TestTimepoint_Equal(t *testing.T) {
	a := NewTimepoint(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	b := NewTimepoint(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	assert.True(t, a.Equal(b))
	assert.False(t, a.Equal(testNow))
}

func TestTimepoint_IsZero(t *testing.T) {
	assert.True(t, ZeroTimepoint.IsZero())
	assert.False(t, testNow.IsZero())
}

func TestTimepoint_String(t *testing.T) {
	tp := NewTimepoint(time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC))
	assert.Equal(t, "2025-06-15T12:00:00Z", tp.String())
}
