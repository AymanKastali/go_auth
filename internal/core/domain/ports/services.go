package ports

import (
	"go_auth/internal/core/domain/aggregates"
	"go_auth/internal/core/domain/entities"
	"go_auth/internal/core/domain/valueobjects"
	"time"
)

type IIDService interface {
	Generate() string
	IsValid(id string) bool
}

type IClockService interface {
	Now() time.Time
}

type IPasswordHasherService interface {
	Hash(raw valueobjects.RawPassword) (valueobjects.HashedPassword, error)
	Compare(plain string, hashed valueobjects.HashedPassword) error
	IsValidFormat(hashed string) bool
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
		now time.Time,
	) (*entities.Device, error)
}

type ISessionDomainService interface {
	// InvalidateExistingSessions ensures security by revoking previous
	// active tokens for a specific user-device pair.
	InvalidateExistingSessions(
		userID valueobjects.UserID,
		deviceID valueobjects.DeviceID,
		now time.Time,
	) error
}
