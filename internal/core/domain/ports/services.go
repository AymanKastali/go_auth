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
	Compare(plain string, hashed valueobjects.HashedPassword) error
	IsValidFormat(hashed string) bool
}

type UserRegistrationPolicy interface {
	Validate(email valueobjects.Email) error
	DefaultRoles() ([]valueobjects.RoleID, error)
}
