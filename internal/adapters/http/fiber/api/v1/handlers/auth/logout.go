package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type LogoutHandler struct {
	uc ports.ILogoutUseCase
}

func NewLogoutHandler(uc ports.ILogoutUseCase) *LogoutHandler {
	return &LogoutHandler{uc: uc}
}

func (h *LogoutHandler) Execute(c *fiber.Ctx) error {
	// 1. Retrieve Auth Context (Hydrated by JWTMiddleware)
	auth, ok := utils.GetAuthContext(c)
	if !ok {
		// If the middleware failed to provide context, it's an Unauthorized state
		return apperr.Unauthorized("session identity missing", "transport-layer", nil)
	}
	traceID := auth.RequestID

	var req dto.LogoutRequest

	// 2. Protocol Layer: Syntax check (HTTP 400)
	if err := c.BodyParser(&req); err != nil {
		// Use the Protocol Adapter for syntax failures
		return http.NewBadRequest(err)
	}

	// 3. Application Layer: Schema validation (HTTP 422)
	if err := utils.Validate(req); err != nil {
		return http.NewBadRequest(err)
	}

	// 4. Use Case Execution
	// UC handles the revocation logic (DB updates, etc.)
	if err := h.uc.Execute(traceID, req.RefreshToken); err != nil {
		// UC returns mapped apperr.AppError (NotFound, Forbidden, etc.)
		return err
	}

	// 5. Success Response: HTTP 204 No Content
	return utils.NoContent(c)
}
