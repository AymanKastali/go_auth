package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/use_cases"

	"github.com/gofiber/fiber/v2"
)

type LogoutHandler struct {
	uc *use_cases.LogoutUseCase
}

func NewLogoutHandler(uc *use_cases.LogoutUseCase) *LogoutHandler {
	return &LogoutHandler{uc: uc}
}

func (h *LogoutHandler) Execute(c *fiber.Ctx) error {
	var req dto.LogoutRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	h.uc.Execute(req.RefreshToken)

	return utils.NoContent(c)
}
