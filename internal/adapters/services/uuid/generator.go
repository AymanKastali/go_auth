package uuid

import (
	"go_auth/internal/core/application/interfaces"
	"go_auth/internal/core/domain/valueobjects"

	"github.com/google/uuid"
)

type UUIDGeneratorService struct{}

var _ interfaces.IUUIDGeneratorService = UUIDGeneratorService{}

func NewUUIDUserIDGenerator() interfaces.IUUIDGeneratorService {
	return &UUIDGeneratorService{}
}

func (UUIDGeneratorService) NewUserID() (valueobjects.UserID, error) {
	raw := uuid.NewString()
	return valueobjects.NewUserID(raw)
}
