package ports

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
)

type IIDService interface {
	Generate() string
	IsValid(id string) bool
}

type IClockService interface {
	Now() valueobjects.Timepoint
}

type IPasswordHasherService interface {
	Hash(raw valueobjects.RawPassword) (valueobjects.HashedPassword, error)
	Compare(raw string, hashed valueobjects.HashedPassword) error
	IsValidFormat(hashed string) bool
}

type IRandomTokenGenerator interface {
	Generate(size int) (string, error)
}

type ITokenHasherService interface {
	Hash(raw string) valueobjects.HashedToken
	Compare(raw string, hashed valueobjects.HashedToken) bool
}

type IUserRegistrationPolicy interface {
	Validate(email valueobjects.Email) error
	DefaultRoles() ([]valueobjects.RoleID, error)
}

type IAuthDomainService interface {
	Authenticate(emailStr, password string) (*aggregates.User, error)
	ResolveDevice(
		deviceFingerprint valueobjects.DeviceFingerprint,
		userID valueobjects.UserID,
		name *string,
		userAgent *string,
		ip *string,
		now valueobjects.Timepoint,
	) (*entities.Device, error)
}

type ISessionDomainService interface {
	InvalidateExistingSessions(
		userID valueobjects.UserID,
		deviceID valueobjects.DeviceID,
		now valueobjects.Timepoint,
	) ([]*entities.RefreshToken, error)

	CreateSession(
		userID valueobjects.UserID,
		deviceID valueobjects.DeviceID,
		expiresAt valueobjects.Timepoint,
		now valueobjects.Timepoint,
	) (*entities.RefreshToken, valueobjects.RawRefreshToken, error)

	RotateSession(
		oldToken *entities.RefreshToken,
		now valueobjects.Timepoint,
	) error
}
