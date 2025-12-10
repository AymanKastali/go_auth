package controllers

import (
	usecases "go_auth/src/application/use_cases"
	"go_auth/src/domain/errors"
	"go_auth/src/presentation/web/fiber/dto/requests"

	"github.com/gofiber/fiber/v2"
)

type RegisterController struct {
	registerUseCase *usecases.RegisterUseCase
}

// Constructor
func NewRegisterController(registerUseCase *usecases.RegisterUseCase) *RegisterController {
	return &RegisterController{
		registerUseCase: registerUseCase,
	}
}

// POST /register
func (ac *RegisterController) Execute(c *fiber.Ctx) error {
	var req requests.RegisterRequest

	// Parse and validate JSON body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// Call use case
	authResp, err := ac.registerUseCase.Execute(req.Email, req.Password)
	if err != nil {
		switch err {
		case errors.ErrEmailAlreadyRegistered:
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": err.Error(),
			})
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
	}

	// Success
	if authResp != nil {
		return c.Status(fiber.StatusCreated).JSON(authResp)
	}

	// If no response (just registration)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "user registered successfully",
	})
}
