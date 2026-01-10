package uuid

import (
	"go_auth/internal/core/application/interfaces"
	"go_auth/internal/core/domain/valueobjects"

	"github.com/google/uuid"
)

type UUIDParserService struct{}

var _ interfaces.IUUIDParserService = UUIDParserService{}

func NewUUIDUserIDParser() interfaces.IUUIDParserService {
	return &UUIDParserService{}
}

func (UUIDParserService) ParseUserID(raw string) (valueobjects.UserID, error) {
	if _, err := uuid.Parse(raw); err != nil {
		return valueobjects.UserID{}, err
	}
	return valueobjects.NewUserID(raw)
}
