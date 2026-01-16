package roles

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	app_dto "go_auth/internal/core/application/dto"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type UpdateRoleHandler struct {
	uc ports.IUpdateRoleUseCase
}

func NewUpdateRoleHandler(uc ports.IUpdateRoleUseCase) *UpdateRoleHandler {
	return &UpdateRoleHandler{uc: uc}
}

func (h *UpdateRoleHandler) Execute(c *fiber.Ctx) error {
	// 1. Retrieve Auth Context (Hydrated by JWTMiddleware)
	auth, ok := utils.GetAuthContext(c)
	if !ok {
		// Strictly an Unauthorized concern if security context is missing
		return apperr.Unauthorized("session identity missing", "transport-layer", nil)
	}
	traceID := auth.RequestID

	var req dto.ManageRoleRequest

	// 2. Protocol Layer: Syntax Check (HTTP 400)
	if err := c.BodyParser(&req); err != nil {
		// Use the Protocol Adapter for infrastructure failures
		return http.NewBadRequest(err)
	}

	// 3. Application Layer: Schema Validation (HTTP 422)
	if err := utils.Validate(req); err != nil {
		return http.NewBadRequest(err)
	}

	// 4. Input Mapping
	// Decouples the HTTP contract from the Core application DTO
	input := app_dto.ManageRoleInput{
		UserID: req.UserID,
		Role:   req.Role,
		Action: req.Action,
	}

	// 5. Core Execution: Business Policy
	// The UC handles permission checks (can the current user do this?) and state updates
	if err := h.uc.Execute(traceID, input); err != nil {
		// Propagates apperr.TypeNotFound, TypeForbidden, or TypeConflict
		return err
	}

	// 6. Success Response: HTTP 204 No Content
	return utils.NoContent(c)
}
