package services

import (
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type clockService struct{}

func NewClockSvc() *clockService { return &clockService{} }

func (s *clockService) Now() valueobjects.Timepoint {
	t := time.Now()
	return valueobjects.ReconstituteTimepoint(t)
}
