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

func (UUIDParserService) ParseDeviceID(raw string) (valueobjects.DeviceID, error) {
	if _, err := uuid.Parse(raw); err != nil {
		return valueobjects.DeviceID{}, err
	}
	return valueobjects.NewDeviceID(raw)
}

func (UUIDParserService) ParseRoleID(raw string) (valueobjects.RoleID, error) {
	if _, err := uuid.Parse(raw); err != nil {
		return valueobjects.RoleID{}, err
	}
	return valueobjects.NewRoleID(raw)
}

func (UUIDParserService) ParseTokenID(raw string) (valueobjects.TokenID, error) {
	if _, err := uuid.Parse(raw); err != nil {
		return valueobjects.TokenID{}, err
	}
	return valueobjects.NewTokenID(raw)
}
