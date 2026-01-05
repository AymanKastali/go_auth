package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	app_dto "go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports/use_cases"

	"github.com/gofiber/fiber/v2"
)

type RoleHandler struct {
	useCase use_cases.ManageRoleUseCasePort
}

func NewRoleHandler(uc use_cases.ManageRoleUseCasePort) *RoleHandler {
	return &RoleHandler{
		useCase: uc,
	}
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

	if err := h.useCase.UpdateRole(input); err != nil {
		return err
	}

	return utils.NoContent(c)

}
