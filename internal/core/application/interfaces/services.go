package interfaces

import (
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type IUUIDGeneratorService interface {
	NewUserID() (valueobjects.UserID, error)
	NewDeviceID() (valueobjects.DeviceID, error)
	NewRoleID() (valueobjects.RoleID, error)
	NewTokenID() (valueobjects.TokenID, error)
}

type IUUIDParserService interface {
	ParseUserID(raw string) (valueobjects.UserID, error)
	ParseDeviceID(raw string) (valueobjects.DeviceID, error)
	ParseRoleID(raw string) (valueobjects.RoleID, error)
	ParseTokenID(raw string) (valueobjects.TokenID, error)
}

type IClock interface {
	Now() time.Time
	NowUTC() time.Time
}
