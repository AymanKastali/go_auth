package query

import "go_auth/internal/application"

// --- Query Inputs ---

type ValidateAccessQuery struct {
	AccessToken        string
	Fingerprint        string
	IncludePermissions bool
}

type ListUsersQuery struct {
	Offset int
	Limit  int
}

// --- Query Responses ---

type ValidateAccessResponse struct {
	UserID      string
	SessionID   string
	Roles       []string
	Permissions []string
}

type ListUsersResponse struct {
	Users []application.UserReadModel
	Total int64
}

// --- Policy DTOs ---

type PasswordPolicyDTO struct {
	MinLength      uint8
	MaxLength      uint8
	RequireUpper   bool
	RequireNumber  bool
	RequireSpecial bool
}

type RegisterPolicyDTO struct {
	AllowPublic    bool
	BlockedDomains []string
}

type ActivationPolicyDTO struct {
	RequireEmail bool
}

type PublicPoliciesResponse struct {
	Password     PasswordPolicyDTO
	Registration RegisterPolicyDTO
	Activation   ActivationPolicyDTO
}

// --- Zero Sentinels ---

var (
	ZeroValidateAccessResponse = ValidateAccessResponse{}
	ZeroPublicPoliciesResponse = PublicPoliciesResponse{}
	ZeroListUsersResponse      = ListUsersResponse{}
)
