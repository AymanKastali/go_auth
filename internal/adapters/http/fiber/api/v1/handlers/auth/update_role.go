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
	uc ports.IUpdateRoleUseCase
}

var _ interfaces.IUpdateRoleHandler = (*updateRoleHandler)(nil)

func NewUpdateRoleHandler(
	uc ports.IUpdateRoleUseCase,
) interfaces.IUpdateRoleHandler {
	return &updateRoleHandler{uc: uc}
}

func (h *updateRoleHandler) Execute(c *fiber.Ctx) error {
	// 1. Extract Identity Context (RequestID/TraceID)
	auth, ok := utils.GetAuthContext(c)
	if !ok {
		// KindUnauthenticated: Maps to 401. Context missing from the request lifecycle.
		return apperr.Unauthenticated("identity not found in context", "system", nil)
	}
	requestID := auth.RequestID

	// 2. TRANSPORT: Parse Web Request Body
	var webReq dto.ManageRoleRequest
	if err := c.BodyParser(&webReq); err != nil {
		// KindInvalid: Maps to 400 Bad Request. Malformed JSON.
		return apperr.Invalid("invalid request body format", requestID, err)
	}

	// 3. Structural Validation
	// Ensure UserID, Role, and Action meet the DTO requirements before mapping
	if err := utils.Validate(webReq); err != nil {
		return apperr.Invalid("validation failed", requestID, err)
	}

	// 4. Map to Application DTO
	// Decouples the Web contract from the internal Use Case input
	input := app_dto.ManageRoleInput{
		UserID: webReq.UserID,
		Role:   webReq.Role,
		Action: webReq.Action,
	}

	// 5. APPLICATION: Execute the Role Management logic
	// Propagates KindNotFound (user/role missing), KindConflict (already assigned), etc.
	if err := h.uc.Execute(requestID, input); err != nil {
		return err
	}

	// 6. SUCCESS: Return 204 No Content for a successful command
	return utils.NoContent(c)
}
