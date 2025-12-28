package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/application/use_cases"

	"github.com/gofiber/fiber/v2"
)

type LogoutHandler struct {
	uc *use_cases.LogoutUseCase
}

func NewLogoutHandler(
	logoutUseCase *use_cases.LogoutUseCase,
) *LogoutHandler {
	return &LogoutHandler{uc: logoutUseCase}
}

func (h *LogoutHandler) Execute(ctx *fiber.Ctx) error {
	var req dto.LogoutRequest

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	return h.uc.Execute(
		req.RefreshToken,
	)
}
