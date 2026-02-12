package outbound

import (
	"go_auth/internal/domain"
	"time"
)

// Clock Service
type clock struct{}

func NewClock() domain.IClock { return &clock{} }

// Now returns the current time in UTC.
func (c *clock) Now() time.Time {
	return time.Now().UTC()
}
