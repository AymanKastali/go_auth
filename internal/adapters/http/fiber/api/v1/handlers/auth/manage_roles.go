package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	app_dto "go_auth/internal/application/dto"
	"go_auth/internal/application/ports/use_cases"

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

func (h *RoleHandler) HandleRoleUpdate(c *fiber.Ctx) error {
	var webReq dto.ManageRoleRequest
	if err := c.BodyParser(&webReq); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "cannot parse JSON: " + err.Error(),
		})
	}

	input := app_dto.ManageRoleInput{
		UserID: webReq.UserID,
		Role:   webReq.Role,
		Action: webReq.Action,
	}

	// 3. Execute the Use Case
	if err := h.useCase.UpdateRole(input); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// return c.Status(fiber.StatusOK).JSON(fiber.Map{
	// 	"message": "Role updated successfully",
	// })

	return utils.Success(c, fiber.StatusNoContent, nil, "")

}
