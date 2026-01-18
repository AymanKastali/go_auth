package services

import (
	"time"
)

type ClockService struct{}

func NewClockSvc() *ClockService {
	return &ClockService{}
}

func (ClockService) Now() time.Time {
	return time.Now()
}
