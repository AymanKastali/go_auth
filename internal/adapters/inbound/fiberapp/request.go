package fiberapp

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type UpdateMeRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required"`
}

type ConfirmActivationRequest struct {
	Token string `json:"token" validate:"required"`
}

type ResendActivationRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// --- Admin: Role Management ---

type CreateRoleRequest struct {
	Name        string   `json:"name" validate:"required"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type AssignPermissionRequest struct {
	Permission string `json:"permission" validate:"required"`
}

type RevokePermissionRequest struct {
	Permission string `json:"permission" validate:"required"`
}

// --- Admin: User Management ---

type AssignUserRoleRequest struct {
	RoleName string `json:"role_name" validate:"required"`
}

type RevokeUserRoleRequest struct {
	RoleName string `json:"role_name" validate:"required"`
}

// --- Token Validation ---

type ValidateTokenRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}
