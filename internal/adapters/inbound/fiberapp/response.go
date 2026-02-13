package fiberapp

import "github.com/gofiber/fiber/v3"

// --- Response Envelopes ---

// DataResponse wraps successful responses that return resource data.
type DataResponse struct {
	Data any `json:"data"`
}

// MessageResponse is used for endpoints that return only a human-readable message
// (e.g., security-sensitive operations where the response must be identical regardless of outcome).
type MessageResponse struct {
	Message string `json:"message" example:"operation completed"`
}

// ErrorBody contains the error details nested under the "error" key.
type ErrorBody struct {
	Code    string         `json:"code" example:"VALIDATION_FAILED"`
	Message string         `json:"message" example:"password length is below the minimum requirement"`
	TraceID string         `json:"trace_id" example:"req-abc123"`
	Details map[string]any `json:"details,omitempty"`
}

// ErrorResponse wraps all error responses under a single "error" key.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// --- Success Helpers ---

// SendOK sends a 200 response with the data wrapped in {"data": ...}.
func SendOK(c fiber.Ctx, data any) error {
	return c.Status(fiber.StatusOK).JSON(DataResponse{Data: data})
}

// SendCreated sends a 201 response with the data wrapped in {"data": ...}.
func SendCreated(c fiber.Ctx, data any) error {
	return c.Status(fiber.StatusCreated).JSON(DataResponse{Data: data})
}

// SendNoContent sends a 204 response with no body.
func SendNoContent(c fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}

// SendMessage sends a 200 response with only a human-readable message.
// Use this for security-sensitive endpoints where the response shape must not
// reveal whether the underlying resource exists (e.g., forgot-password).
func SendMessage(c fiber.Ctx, message string) error {
	return c.Status(fiber.StatusOK).JSON(MessageResponse{Message: message})
}

// --- Error Helpers ---

// SendError sends a structured error response with the given HTTP status code.
func SendError(c fiber.Ctx, status int, code, message string, details map[string]any) error {
	return c.Status(status).JSON(ErrorResponse{
		Error: ErrorBody{
			Code:    code,
			Message: message,
			TraceID: c.GetRespHeader("X-Request-ID"),
			Details: details,
		},
	})
}

// SendBadRequest sends a 400 error for malformed requests or binding failures.
func SendBadRequest(c fiber.Ctx, message string) error {
	return SendError(c, fiber.StatusBadRequest, "BAD_REQUEST", message, nil)
}

// SendUnauthorized sends a 401 error for missing or invalid credentials.
func SendUnauthorized(c fiber.Ctx, message string) error {
	return SendError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", message, nil)
}

// SendForbidden sends a 403 error for insufficient permissions.
func SendForbidden(c fiber.Ctx, message string) error {
	return SendError(c, fiber.StatusForbidden, "FORBIDDEN", message, nil)
}

// SendInternalError sends a 500 error for unexpected server failures.
func SendInternalError(c fiber.Ctx, message string) error {
	return SendError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", message, nil)
}

// SendServiceUnavailable sends a 503 error when a dependency is not ready.
func SendServiceUnavailable(c fiber.Ctx, message string) error {
	return SendError(c, fiber.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", message, nil)
}

// --- Domain-Specific Response DTOs ---

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
	ID           string `json:"id"`
	Email        string `json:"email"`
	RegisteredAt string `json:"registered_at"`
	UpdatedAt    string `json:"updated_at"`
}

type HealthResponse struct {
	Status string `json:"status" example:"healthy"`
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
	Password     PasswordPolicyHTTPResponse   `json:"password"`
	Registration RegisterPolicyHTTPResponse   `json:"registration"`
	Activation   ActivationPolicyHTTPResponse `json:"activation"`
}

type ValidateTokenResponse struct {
	UserID      string   `json:"user_id"`
	SessionID   string   `json:"session_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions,omitempty"`
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
