package ports

import "time"

type IIDService interface {
	Generate() string
	IsValid(id string) bool
}

type IClockService interface {
	Now() time.Time
}

type IPasswordService interface {
	Hash(raw string) (string, error)
	Compare(raw string, hashed string) bool
	IsValidHash(hashed string) bool
}
