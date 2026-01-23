package roles

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	app_dto "go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

type UpdateRoleHandler struct {
	uc ports.IUpdateRoleUseCase
}

func NewUpdateRoleHandler(uc ports.IUpdateRoleUseCase) *UpdateRoleHandler {
	return &UpdateRoleHandler{uc: uc}
}

// Execute handles the role management action
// @Summary      Manage User Roles
// @Tags         roles
// @Accept       json
// @Produce      json
// @Param        request  body      dto.ManageRoleRequest  true  "Role management details"
// @Success      204      {object}  nil
// @Failure      400      {object}  dto.ErrorResponse
// @Router       /roles/manage [post]
func (h *UpdateRoleHandler) Execute(c fiber.Ctx) error {
	// 1. Get technical context (Middleware Logger + Auth Data)
	auth, ok := utils.AuthFromContext(c.Context())
	l := utils.FromContext(c.Context()).Logger
	if ok {
		l = auth.Logger
	}

	var req dto.ManageRoleRequest

	// 2. BIND FIRST (This populates the 'req' struct)
	if err := c.Bind().Body(&req); err != nil {
		l.Warn("Failed to parse role update request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	// 3. VALIDATE SECOND (Ensures data is sane)
	if err := utils.Validate(req); err != nil {
		l.Warn("Role update request validation failed", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	// 4. NOW LOG (Data is present after Bind and Validate)
	l.Info("Handling role update request",
		slog.String("target_user_id", req.UserID),
		slog.String("role", req.Role),
		slog.String("action", req.Action),
	)

	// 5. MAP to Application Input
	input := app_dto.ManageRoleInput{
		UserID: req.UserID,
		Role:   req.Role,
		Action: req.Action,
	}

	// 6. EXECUTE (Pass technical dependency 'l' and business data 'input')
	if err := h.uc.Execute(l, input); err != nil {
		// UseCase already handles internal logging
		return err
	}

	l.Info("User role update completed",
		slog.String("target_user_id", req.UserID),
		slog.String("role", req.Role),
		slog.String("action", req.Action),
	)

	return c.SendStatus(fiber.StatusNoContent)
}
