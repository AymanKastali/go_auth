package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type logoutHandler struct {
	uc ports.ILogoutUseCase
}

var _ interfaces.ILogoutHandler = (*logoutHandler)(nil)

func NewLogoutHandler(
	uc ports.ILogoutUseCase,
) interfaces.ILogoutHandler {
	return &logoutHandler{uc: uc}
}

func (h *logoutHandler) Execute(c *fiber.Ctx) error {
	// 1. Extract Identity Context (TraceID/RequestID)
	auth, ok := utils.GetAuthContext(c)
	if !ok {
		// KindUnauthenticated: The identity is missing from the request lifecycle
		return apperr.Unauthenticated("identity not found in context", "system", nil)
	}
	requestID := auth.RequestID

	var req dto.LogoutRequest

	// 2. Parse request body
	if err := c.BodyParser(&req); err != nil {
		// KindInvalid: The JSON itself is malformed
		return apperr.Invalid("invalid request body format", requestID, err)
	}

	// 3. Structural Validation
	// This checks if the RefreshToken field is present/meets basic criteria
	if err := utils.Validate(req); err != nil {
		// KindInvalid: Required fields are missing from the DTO
		return apperr.Invalid("validation failed: refresh token is required", requestID, err)
	}

	// 4. Business Logic Orchestration
	// UseCase will handle finding the token and updating the DB state
	if err := h.uc.Execute(requestID, req.RefreshToken); err != nil {
		// Propagates KindNotFound (404) or KindConflict (409) if already revoked
		return err
	}

	// 5. SUCCESS: HTTP 204
	return utils.NoContent(c)
}
