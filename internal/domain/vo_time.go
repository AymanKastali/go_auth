package domain

import "time"

var ZeroTimepoint = Timepoint{}

// --- Timepoint ---
type Timepoint struct{ time time.Time }

func NewTimepoint(t time.Time) Timepoint           { return Timepoint{time: t.UTC()} }
func ReconstituteTimepoint(t time.Time) Timepoint  { return Timepoint{time: t.UTC()} }
func (vo Timepoint) Time() time.Time               { return vo.time }
func (vo Timepoint) IsBefore(other Timepoint) bool { return vo.time.Before(other.time) }
func (vo Timepoint) IsAfter(other Timepoint) bool  { return vo.time.After(other.time) }
func (vo Timepoint) Add(d time.Duration) Timepoint { return Timepoint{time: vo.time.Add(d)} }
func (vo Timepoint) Equal(other Timepoint) bool    { return vo.time.Equal(other.time) }
func (vo Timepoint) String() string                { return vo.time.Format(time.RFC3339) }
func (vo Timepoint) IsZero() bool                  { return vo.time.IsZero() }
