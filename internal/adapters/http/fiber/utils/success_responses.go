package utils

import (
	"go_auth/internal/adapters/http/fiber/dto"

	"github.com/gofiber/fiber/v3"
)

// Success response
func success(c fiber.Ctx, statusCode int, data any, message string) error {
	if statusCode == fiber.StatusNoContent {
		return c.SendStatus(fiber.StatusNoContent)
	}

	return c.Status(statusCode).JSON(dto.SuccessResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

// OK returns a 200 Status OK response
func OK(c fiber.Ctx, data any, message string) error {
	return success(c, fiber.StatusOK, data, message)
}

// Created returns a 201 Status Created response
func Created(c fiber.Ctx, data any, message string) error {
	return success(c, fiber.StatusCreated, data, message)
}

// NoContent returns a 204 Status No Content response
func NoContent(c fiber.Ctx) error {
	return success(c, fiber.StatusNoContent, nil, "")
}
