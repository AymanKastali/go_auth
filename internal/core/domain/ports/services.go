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
	Now() (valueobjects.Timepoint, error)
}

type IPasswordHasherService interface {
	Hash(raw valueobjects.RawPassword) (valueobjects.HashedPassword, error)
	Compare(raw valueobjects.RawPassword, hashed valueobjects.HashedPassword) error
	IsValidFormat(hashed string) bool
}

type IRandomTokenGenerator interface {
	Generate() (valueobjects.SessionRenewalRawTokenSecret, error)
}

type ITokenHasherService interface {
	Hash(raw valueobjects.SessionRenewalRawTokenSecret) (valueobjects.SessionRenewalHashedToken, error)
	Compare(raw valueobjects.SessionRenewalRawTokenSecret, hash valueobjects.SessionRenewalHashedToken) (bool, error)
}

type IUserRegistrationPolicy interface {
	Validate(email valueobjects.Email) error
	DefaultRoles() ([]valueobjects.RoleID, error)
}

type IAuthDomainService interface {
	Authenticate(emailStr, password string) (*aggregates.User, error)
	ResolveDevice(
		fingerprint valueobjects.DeviceFingerprint,
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
	) ([]*entities.SessionRenewalToken, error)

	CreateSession(
		userID valueobjects.UserID,
		deviceID valueobjects.DeviceID,
		now valueobjects.Timepoint,
	) (*entities.SessionRenewalToken, valueobjects.SessionRenewalRawToken, error)

	RotateSession(
		oldToken *entities.SessionRenewalToken,
		now valueobjects.Timepoint,
	) error

	RevokeSession(
		token *entities.SessionRenewalToken,
		rawSecret valueobjects.SessionRenewalRawTokenSecret,
		now valueobjects.Timepoint,
	) error

	RefreshSession(
		oldToken *entities.SessionRenewalToken,
		rawSecret valueobjects.SessionRenewalRawTokenSecret,
		currentDevice *entities.Device,
		now valueobjects.Timepoint,
	) (*entities.SessionRenewalToken, valueobjects.SessionRenewalRawToken, error)
}

type IPasswordPolicyService interface {
	Validate(password valueobjects.RawPassword) error
}

type IUserService interface {
	RegisterUser(email valueobjects.Email, rawPwd valueobjects.RawPassword, now valueobjects.Timepoint) (*aggregates.User, error)
	AssignRole(user *aggregates.User, roleName string, now valueobjects.Timepoint) error
	RemoveRole(user *aggregates.User, roleName string, now valueobjects.Timepoint) error
}

type IRoleService interface {
	EnsureRoleExists(name string, now valueobjects.Timepoint) (*aggregates.Role, error)
	CreateNewRole(name string, now valueobjects.Timepoint) (*aggregates.Role, error)
}
