package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

type LogoutHandler struct {
	uc ports.ILogoutUseCase
}

func NewLogoutHandler(uc ports.ILogoutUseCase) *LogoutHandler {
	return &LogoutHandler{uc: uc}
}

func (h *LogoutHandler) Execute(c *fiber.Ctx) error {
	reqCtx := utils.ReqCtx(c)
	l := reqCtx.Logger

	var req dto.LogoutRequest

	l.Info("Handling logout request")

	if err := c.BodyParser(&req); err != nil {
		l.Warn("Failed to parse logout request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	if err := utils.Validate(req); err != nil {
		l.Warn("Logout request validation failed", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	if err := h.uc.Execute(
		c.UserContext(),
		req.RefreshToken,
	); err != nil {
		l.Warn("Logout execution failed", slog.Any("error", err))
		return err
	}

	l.Info("User logged out successfully")

	return utils.NoContent(c)
}
