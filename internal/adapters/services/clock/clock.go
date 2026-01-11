package clock

import (
	"go_auth/internal/core/application/interfaces"
	"time"
)

type ClockService struct{}

func NewClockService() interfaces.IClock {
	return &ClockService{}
}

func (ClockService) Now() time.Time {
	return time.Now()
}

func (ClockService) NowUTC() time.Time {
	return time.Now().UTC()
}
