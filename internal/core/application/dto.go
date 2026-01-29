package application

import "time"

var (
	ZeroLoginResponse          = LoginResponse{}
	ZeroRegisterUserResponse   = RegisterUserResponse{}
	ZeroValidateAccessResponse = ValidateAccessResponse{}
	ZeroUserResponse           = UserResponse{}
)

// RegisterUserCommand
type RegisterUserCommand struct {
	Email    string
	Password string
}

// LoginCommand
type LoginCommand struct {
	Email          string
	Password       string
	IPAddress      string
	OS             string
	Browser        string
	Model          string
	AcceptLanguage string
	UserAgent      string
	IsMobile       bool
}

// RefreshTokenCommand
type RefreshTokenCommand struct {
	UserID       string
	RefreshToken string
	Fingerprint  string
}

// LogoutCommand
type LogoutCommand struct {
	UserID    string
	SessionID string
}

// ValidateAccessQuery
type ValidateAccessQuery struct {
	AccessToken string
	Fingerprint string // Optional: check if you embed FP in the JWT
}

type ValidateAccessResponse struct {
	UserID    string
	SessionID string
	Roles     []string
}

// UpdateMeCommand
type UpdateMeCommand struct {
	Email string
}

// ChangePassword
type ChangePasswordCommand struct {
	OldPassword string
	NewPassword string
}

// LoginResponse (The Dual-Token DTO)
type LoginResponse struct {
	AccessToken        string
	AccessTokenExpiry  string
	RefreshToken       string
	RefreshTokenExpiry string
}

type RegisterUserResponse struct {
	UserID string
	Email  string
}

type FindUserByEmailQuery struct {
	Email string
}

type UserResponse struct {
	ID        string
	Email     string
	CreatedAT time.Time
}
