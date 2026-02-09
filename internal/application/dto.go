package application

import "time"

var (
	ZeroLoginResponse           = LoginResponse{}
	ZeroRegisterUserResponse    = RegisterUserResponse{}
	ZeroValidateAccessResponse  = ValidateAccessResponse{}
	ZeroUserReadModel           = UserReadModel{}
	ZeroPublicPoliciesResponse  = PublicPoliciesResponse{}
	ZeroRoleReadModel           = RoleReadModel{}
	ZeroListUsersResponse       = ListUsersResponse{}
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

type ForgotPasswordCommand struct {
	Email string
}

// ResetPassword
type ResetPasswordCommand struct {
	Token       string
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

type UserReadModel struct {
	ID           string
	Email        string
	IsActive     bool
	Roles        []string
	RegisteredAt time.Time
	UpdatedAt    time.Time
}

// PasswordPolicyDTO exposes password requirements to clients.
type PasswordPolicyDTO struct {
	MinLength      uint8
	MaxLength      uint8
	RequireUpper   bool
	RequireNumber  bool
	RequireSpecial bool
}

// RegisterPolicyDTO exposes registration rules to clients.
type RegisterPolicyDTO struct {
	AllowPublic    bool
	BlockedDomains []string
}

// ActivationPolicyDTO exposes activation requirements to clients.
type ActivationPolicyDTO struct {
	RequireEmail bool
}

// PublicPoliciesResponse is the aggregate response for the public policies endpoint.
type PublicPoliciesResponse struct {
	Password     PasswordPolicyDTO
	Registration RegisterPolicyDTO
	Activation   ActivationPolicyDTO
}

// ConfirmActivationCommand
type ConfirmActivationCommand struct {
	Token string
}

// ResendActivationCommand
type ResendActivationCommand struct {
	Email string
}

// --- Admin: Role Management ---

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

// --- Admin: User Management ---

type AssignUserRoleCommand struct {
	UserID   string
	RoleName string
}

type RevokeUserRoleCommand struct {
	UserID   string
	RoleName string
}

type ListUsersQuery struct {
	Offset int
	Limit  int
}

// --- Admin: Response Models ---

type RoleReadModel struct {
	ID          string
	Name        string
	Description string
	Permissions []string
}

type ListUsersResponse struct {
	Users []UserReadModel
	Total int64
}
