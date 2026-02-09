package outbound

import (
	"go_auth/internal/domain"
	"time"
)

// Clock Service
type clock struct{}

func NewClock() domain.IClock { return &clock{} }

// Now returns the current time wrapped in the Domain Value Object.
func (c *clock) Now() domain.Timepoint {
	// We strip monotonic clock readings and normalize to UTC
	// to ensure DB compatibility and consistent comparisons.
	return domain.NewTimepoint(time.Now().UTC())
}
