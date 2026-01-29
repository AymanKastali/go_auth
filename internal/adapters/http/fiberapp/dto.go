package fiberapp

import "github.com/gofiber/fiber/v3"

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

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
	ID    string `json:"id"`
	Email string `json:"email"`
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
