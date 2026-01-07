package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	app_dto "go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type updateRoleHandler struct {
	uc ports.UpdateRoleUseCasePort
}

var _ interfaces.IUpdateRoleHandler = (*updateRoleHandler)(nil)

func NewUpdateRoleHandler(
	uc ports.UpdateRoleUseCasePort,
) interfaces.IUpdateRoleHandler {
	return &updateRoleHandler{uc: uc}
}

func (h *updateRoleHandler) Execute(c *fiber.Ctx) error {
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
