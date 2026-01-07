package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	app_dto "go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/use_cases"

	"github.com/gofiber/fiber/v2"
)

type RoleHandler struct {
	uc *use_cases.UpdateRoleUseCase
}

func NewUpdateRoleHandler(uc *use_cases.UpdateRoleUseCase) *RoleHandler {
	return &RoleHandler{uc: uc}
}

func (h *RoleHandler) Execute(c *fiber.Ctx) error {
	var webReq dto.ManageRoleRequest
	if err := c.BodyParser(&webReq); err != nil {
		return apperr.NewBadRequestErr(err.Error())
	}

	input := app_dto.ManageRoleInput{
		UserID: webReq.UserID,
		Role:   webReq.Role,
		Action: webReq.Action,
	}

	if err := h.uc.Execute(input); err != nil {
		return err
	}

	return utils.NoContent(c)

}
