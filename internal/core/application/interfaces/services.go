package interfaces

import "go_auth/internal/core/domain/valueobjects"

type IUUIDGeneratorService interface {
	NewUserID() (valueobjects.UserID, error)
}

type IUUIDParserService interface {
	ParseUserID(raw string) (valueobjects.UserID, error)
}
