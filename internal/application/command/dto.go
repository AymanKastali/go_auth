package command

import "go_auth/internal/application"

// --- Command Inputs ---

type RegisterUserCommand struct {
	Email    string
	Password string
}

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

type RefreshTokenCommand struct {
	UserID       string
	RefreshToken string
	Fingerprint  string
}

type LogoutCommand struct {
	UserID    string
	SessionID string
}

type UpdateMeCommand struct {
	Email string
}

type ChangePasswordCommand struct {
	OldPassword string
	NewPassword string
}

type ForgotPasswordCommand struct {
	Email string
}

type ResetPasswordCommand struct {
	Token       string
	NewPassword string
}

type ConfirmActivationCommand struct {
	Token string
}

type ResendActivationCommand struct {
	Email string
}

type CreateRoleCommand struct {
	Name        string
	Description string
	Permissions []string
}

type AssignPermissionCommand struct {
	RoleID     string
	Permission string
}

type RevokePermissionCommand struct {
	RoleID     string
	Permission string
}

type AssignUserRoleCommand struct {
	UserID   string
	RoleName string
}

type RevokeUserRoleCommand struct {
	UserID   string
	RoleName string
}

// --- Command Responses ---

type RegisterUserResponse struct {
	UserID string
	Email  string
}

type LoginResponse struct {
	AccessToken        string
	AccessTokenExpiry  string
	RefreshToken       string
	RefreshTokenExpiry string
}

// --- Zero Sentinels ---

var (
	ZeroLoginResponse        = LoginResponse{}
	ZeroRegisterUserResponse = RegisterUserResponse{}
	ZeroRoleReadModel        = application.ZeroRoleReadModel
)

// --- Seed Types ---

type RoleSeedDefinition struct {
	Name        string
	Description string
	Permissions []string
}
