package valueobjects

import (
	"go_auth/internal/core/domain/derr"
	"time"
)

type Timepoint struct{ t time.Time }

func NewTimepoint(t time.Time) (Timepoint, error) {
	if t.IsZero() {
		return Timepoint{}, derr.NewErrTimepointRequired()
	}
	return Timepoint{t: t.UTC()}, nil
}

func ReconstituteTimepoint(t time.Time) Timepoint { return Timepoint{t: t.UTC()} }

func (vo Timepoint) Time() time.Time               { return vo.t }
func (vo Timepoint) IsBefore(other Timepoint) bool { return vo.t.Before(other.t) }
func (vo Timepoint) IsAfter(other Timepoint) bool  { return vo.t.After(other.t) }
func (vo Timepoint) IsFuture(other Timepoint) bool { return vo.t.After(other.t) }
func (vo Timepoint) Add(d time.Duration) Timepoint { return Timepoint{t: vo.t.Add(d)} }
func (vo Timepoint) Equal(other Timepoint) bool    { return vo.t.Equal(other.t) }
func (vo Timepoint) String() string                { return vo.t.Format(time.RFC3339) }
func (vo Timepoint) IsZero() bool                  { return vo.t.IsZero() }
