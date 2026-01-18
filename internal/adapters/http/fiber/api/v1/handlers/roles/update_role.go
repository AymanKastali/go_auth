package roles

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	app_dto "go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

type UpdateRoleHandler struct {
	uc ports.IUpdateRoleUseCase
}

func NewUpdateRoleHandler(uc ports.IUpdateRoleUseCase) *UpdateRoleHandler {
	return &UpdateRoleHandler{uc: uc}
}

func (h *UpdateRoleHandler) Execute(c *fiber.Ctx) error {
	reqCtx := utils.ReqCtx(c)
	l := reqCtx.Logger

	var req dto.ManageRoleRequest

	l.Info("Handling role update request")

	if err := c.BodyParser(&req); err != nil {
		l.Warn("Failed to parse role update request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	l.Debug("Validating role update data",
		slog.String("target_user_id", req.UserID),
		slog.String("role", req.Role),
		slog.String("action", req.Action),
	)

	if err := utils.Validate(req); err != nil {
		l.Warn("Role update request validation failed",
			slog.String("target_user_id", req.UserID),
			slog.Any("error", err),
		)
		return http.NewBadRequest(err)
	}

	input := app_dto.ManageRoleInput{
		UserID: req.UserID,
		Role:   req.Role,
		Action: req.Action,
	}

	if err := h.uc.Execute(
		c.UserContext(),
		input,
	); err != nil {
		l.Warn("Role update execution failed",
			slog.String("target_user_id", req.UserID),
			slog.Any("error", err),
		)
		return err
	}

	l.Info("User role updated successfully",
		slog.String("target_user_id", req.UserID),
		slog.String("role", req.Role),
		slog.String("action", req.Action),
	)

	return utils.NoContent(c)
}
