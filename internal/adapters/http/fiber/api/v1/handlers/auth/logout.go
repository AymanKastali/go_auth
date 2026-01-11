package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type logoutHandler struct {
	uc ports.LogoutUseCasePort
}

var _ interfaces.ILogoutHandler = (*logoutHandler)(nil)

func NewLogoutHandler(
	uc ports.LogoutUseCasePort,
) interfaces.ILogoutHandler {
	return &logoutHandler{uc: uc}
}

func (h *logoutHandler) Execute(c *fiber.Ctx) error {
	var req dto.LogoutRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	if err := h.uc.Execute(req.RefreshToken); err != nil {
		return err
	}

	return utils.NoContent(c)
}
