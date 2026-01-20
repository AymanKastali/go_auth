package ports

import (
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
	Compare(raw string, hashed valueobjects.HashedPassword) error
	IsValidFormat(hashed string) bool
}

type IRandomTokenGenerator interface {
	Generate(size int) (string, error)
}

type ITokenHasherService interface {
	Hash(raw string) (valueobjects.HashedToken, error)
	Compare(raw string, hashed valueobjects.HashedToken) bool
}

type IUserRegistrationPolicy interface {
	Validate(email valueobjects.Email) error
	DefaultRoles() ([]valueobjects.RoleID, error)
}
