package utils

import (
	"go_auth/internal/adapters/http/fiber/dto"

	"github.com/gofiber/fiber/v2"
)

// Success response
func Success(c *fiber.Ctx, statusCode int, data any, message string) error {
	if statusCode == fiber.StatusNoContent {
		return c.SendStatus(fiber.StatusNoContent)
	}

	return c.Status(statusCode).JSON(dto.SuccessResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// Error response
func Failure(c *fiber.Ctx, statusCode int, message string, field string) error {
	return c.Status(statusCode).JSON(dto.ErrorResponse{
		Success: false,
		Message: message,
		Field:   field,
	})
}
