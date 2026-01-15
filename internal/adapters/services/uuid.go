package services

import "github.com/google/uuid"

type UUIDService struct{}

func NewUUIDService() *UUIDService {
	return &UUIDService{}
}

func (s *UUIDService) Generate() string {
	return uuid.New().String()
}

func (s *UUIDService) IsValid(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}
