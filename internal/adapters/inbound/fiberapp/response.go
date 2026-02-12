package fiberapp

import "github.com/gofiber/fiber/v3"

type LoginResponse struct {
	AccessToken        string `json:"access_token"`
	AccessTokenExpiry  string `json:"access_exp"`
	RefreshToken       string `json:"refresh_token"`
	RefreshTokenExpiry string `json:"refresh_exp"`
}

type RegisterUserResponse struct {
	UserID string `json:"id"`
	Email  string `json:"email"`
}

type UserResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	RegisteredAt string `json:"registered_at"`
	UpdatedAt string `json:"updated_at"`
}

type PasswordPolicyHTTPResponse struct {
	MinLength      uint8 `json:"min_length" example:"8"`
	MaxLength      uint8 `json:"max_length" example:"64"`
	RequireUpper   bool  `json:"require_upper" example:"true"`
	RequireNumber  bool  `json:"require_number" example:"true"`
	RequireSpecial bool  `json:"require_special" example:"true"`
}

type RegisterPolicyHTTPResponse struct {
	AllowPublic    bool     `json:"allow_public" example:"true"`
	BlockedDomains []string `json:"blocked_domains"`
}

type ActivationPolicyHTTPResponse struct {
	RequireEmail bool `json:"require_email" example:"false"`
}

type PolicyHTTPResponse struct {
	Password     PasswordPolicyHTTPResponse    `json:"password"`
	Registration RegisterPolicyHTTPResponse    `json:"registration"`
	Activation   ActivationPolicyHTTPResponse  `json:"activation"`
}

type SuccessResponse struct {
	Message string `json:"message,omitempty" example:"humanized success message"`
	Data    any    `json:"data,omitempty"`
}

type ErrorResponse struct {
	Code    string         `json:"code" example:"VALIDATION"`
	Message string         `json:"message" example:"humanized error message"`
	TraceID string         `json:"trace_id" example:"req-12345"`
	Details map[string]any `json:"details,omitempty"`
}

// Success
func SendOK(c fiber.Ctx, message string, data any) error {
	return c.Status(fiber.StatusOK).JSON(SuccessResponse{
		Message: message,
		Data:    data,
	})
}
func SendCreated(c fiber.Ctx, message string, data any) error {
	return c.Status(fiber.StatusCreated).JSON(SuccessResponse{
		Message: message,
		Data:    data,
	})
}
func SendNoContent(c fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}

// Error
func SendError(c fiber.Ctx, status int, code, message string, details map[string]any) error {
	return c.Status(status).JSON(ErrorResponse{
		Code:    code,
		Message: message,
		TraceID: c.GetRespHeader("X-Request-ID"), // Assumes you use RequestID middleware
		Details: details,
	})
}

func SendBadRequest(c fiber.Ctx, message string, details map[string]any) error {
	return SendError(c, fiber.StatusBadRequest, "BAD_REQUEST", message, details)
}

// SendUnauthorized handles 401 errors (e.g., invalid credentials or expired tokens)
func SendUnauthorized(c fiber.Ctx, message string) error {
	return SendError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", message, nil)
}

// SendInternalError handles 500 errors (e.g., database failure)
func SendInternalError(c fiber.Ctx, message string) error {
	return SendError(c, fiber.StatusInternalServerError, "INTERNAL_SERVER_ERROR", message, nil)
}

// SendForbidden handles 403 errors (e.g., insufficient role)
func SendForbidden(c fiber.Ctx, message string) error {
	return SendError(c, fiber.StatusForbidden, "FORBIDDEN", message, nil)
}

// SendServiceUnavailable handles 503 errors (e.g., dependency not ready)
func SendServiceUnavailable(c fiber.Ctx, message string) error {
	return SendError(c, fiber.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", message, nil)
}

// --- Admin Response Types ---

type RoleHTTPResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type AdminUserResponse struct {
	ID           string   `json:"id"`
	Email        string   `json:"email"`
	IsActive     bool     `json:"is_active"`
	Roles        []string `json:"roles"`
	RegisteredAt string   `json:"registered_at"`
	UpdatedAt    string   `json:"updated_at"`
}

type ListUsersHTTPResponse struct {
	Users  []AdminUserResponse `json:"users"`
	Total  int64               `json:"total"`
	Offset int                 `json:"offset"`
	Limit  int                 `json:"limit"`
}

type ValidateTokenResponse struct {
	UserID      string   `json:"user_id"`
	SessionID   string   `json:"session_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions,omitempty"`
}
