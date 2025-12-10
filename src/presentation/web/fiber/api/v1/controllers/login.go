package controllers

import (
	usecases "go_auth/src/application/use_cases"
	"go_auth/src/domain/errors"
	"go_auth/src/presentation/web/fiber/dto/requests"

	"github.com/gofiber/fiber/v2"
)

type LoginController struct {
	loginUseCase *usecases.LoginUseCase
}

// Constructor
func NewLoginController(loginUseCase *usecases.LoginUseCase) *LoginController {
	return &LoginController{
		loginUseCase: loginUseCase,
	}
}

// POST /login
func (lc *LoginController) Execute(c *fiber.Ctx) error {
	var req requests.LoginRequest

	// Parse and validate JSON body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// Call use case
	authResp, err := lc.loginUseCase.Execute(req.Email, req.Password)
	if err != nil {
		switch err {
		case errors.ErrInvalidCredentials:
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
	}

	// Success
	return c.Status(fiber.StatusOK).JSON(authResp)
}
