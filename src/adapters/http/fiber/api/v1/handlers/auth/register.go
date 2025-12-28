package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/application/use_cases"
	"go_auth/src/domain/errors"

	"github.com/gofiber/fiber/v2"
)

type RegisterHandler struct {
	uc *use_cases.RegisterUseCase
}

func NewRegisterHandler(
	registerUseCase *use_cases.RegisterUseCase,
) *RegisterHandler {
	return &RegisterHandler{uc: registerUseCase}
}

func (h *RegisterHandler) Execute(c *fiber.Ctx) error {
	var req dto.RegisterRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	authResp, err := h.uc.Execute(req.Email, req.Password)
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

	if authResp != nil {
		return c.Status(fiber.StatusCreated).JSON(authResp)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "user registered successfully",
	})
}
