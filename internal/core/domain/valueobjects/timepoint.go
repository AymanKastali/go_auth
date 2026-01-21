package valueobjects

import (
	"time"
)

type Timepoint struct {
	value time.Time
}

func ReconstituteTimepoint(t time.Time) Timepoint { return Timepoint{value: t.UTC()} }

func (t Timepoint) Value() time.Time              { return t.value }
func (t Timepoint) IsBefore(other Timepoint) bool { return t.value.Before(other.value) }
func (t Timepoint) IsAfter(other Timepoint) bool  { return t.value.After(other.value) }
func (t Timepoint) IsFuture(other Timepoint) bool { return t.value.After(other.value) }
func (t Timepoint) Add(d time.Duration) Timepoint { return Timepoint{value: t.value.Add(d)} }
func (t Timepoint) Equal(other Timepoint) bool    { return t.value.Equal(other.value) }
func (t Timepoint) String() string                { return t.value.Format(time.RFC3339) }
func (t Timepoint) IsZero() bool                  { return t.value.IsZero() }
