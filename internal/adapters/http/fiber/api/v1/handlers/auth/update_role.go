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
	// 1. Extract TraceID from locals (injected by JWTMiddleware)
	auth, ok := utils.GetAuthContext(c)
	if !ok {
		// This should theoretically never happen if JWTMiddleware is present
		return apperr.Unauthorized("identity not found in context", "system", nil)
	}
	requestID := auth.RequestID

	// 2. Parse Web Request Body
	var webReq dto.ManageRoleRequest
	if err := c.BodyParser(&webReq); err != nil {
		// Use BadRequest to signal invalid JSON input
		return apperr.BadRequest("invalid request body format", requestID, err)
	}

	// 3. Map to Application DTO
	input := app_dto.ManageRoleInput{
		UserID: webReq.UserID,
		Role:   webReq.Role,
		Action: webReq.Action,
	}

	// 4. Call Use Case with (requestID, input)
	if err := h.uc.Execute(requestID, input); err != nil {
		// The Use Case already returns a properly wrapped apperr.AppError
		return err
	}

	return utils.NoContent(c)
}
