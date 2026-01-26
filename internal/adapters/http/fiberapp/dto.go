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

type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
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
