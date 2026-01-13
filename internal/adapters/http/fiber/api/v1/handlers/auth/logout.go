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
	uc ports.LogoutUseCasePort
}

var _ interfaces.ILogoutHandler = (*logoutHandler)(nil)

func NewLogoutHandler(
	uc ports.LogoutUseCasePort,
) interfaces.ILogoutHandler {
	return &logoutHandler{uc: uc}
}

func (h *logoutHandler) Execute(c *fiber.Ctx) error {
	// 1. Extract TraceID (Required for the AppError system)
	traceID, _ := c.Locals("trace_id").(string)
	if traceID == "" {
		traceID = c.Get("X-Request-ID", "logout-flow")
	}

	var req dto.LogoutRequest

	// 2. TRANSPORT: Parse request body
	if err := c.BodyParser(&req); err != nil {
		// Use BadRequest to trigger the GlobalErrorHandler's 400 logic
		return apperr.BadRequest("invalid request body", traceID, err)
	}

	// 3. APPLICATION: Call use case with (traceID, refreshToken)
	// This matches the updated Execute(string, string) signature
	if err := h.uc.Execute(traceID, req.RefreshToken); err != nil {
		// Bubbles up apperr.NotFound (if already logged out) or apperr.Internal
		return err
	}

	// 4. SUCCESS: Return 204 No Content
	return utils.NoContent(c)
}
