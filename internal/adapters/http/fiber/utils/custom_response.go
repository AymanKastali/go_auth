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

	return c.Status(statusCode).JSON(dto.APIResponse{
		Status:  "success",
		Message: message,
		Data:    data,
	})
}

// Error response
func Failure(c *fiber.Ctx, statusCode int, message string, errors any) error {
	return c.Status(statusCode).JSON(dto.APIResponse{
		Status:  "error",
		Message: message,
		Errors:  errors,
	})
}
