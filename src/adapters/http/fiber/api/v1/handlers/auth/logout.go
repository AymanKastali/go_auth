package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/application/ports/use_cases"

	"github.com/gofiber/fiber/v2"
)

type LogoutHandler struct {
	useCase use_cases.LogoutUserUseCasePort
}

func NewLogoutHandler(
	uc use_cases.LogoutUserUseCasePort,
) *LogoutHandler {
	return &LogoutHandler{useCase: uc}
}

func (h *LogoutHandler) Execute(ctx *fiber.Ctx) error {
	var req dto.LogoutRequest

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	return h.useCase.Logout(
		req.RefreshToken,
	)
}
