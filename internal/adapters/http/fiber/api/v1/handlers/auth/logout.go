package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

type LogoutHandler struct {
	uc ports.ILogoutUseCase
}

func NewLogoutHandler(uc ports.ILogoutUseCase) *LogoutHandler {
	return &LogoutHandler{uc: uc}
}

// Execute handles the user logout process.
// @Summary      User Logout
// @Description  Invalidates the provided session renewal token (refresh token).
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      dto.LogoutRequest  true  "Logout Details"
// @Success      204      "Successfully logged out"
// @Failure      400      {object}  dto.ErrorResponse  "Invalid request body or validation failed"
// @Failure      401      {object}  dto.ErrorResponse  "Unauthorized - Invalid or expired token"
// @Failure      500      {object}  dto.ErrorResponse  "Internal server error"
// @Router       /auth/logout [post]
func (h *LogoutHandler) Execute(c fiber.Ctx) error {
	// 1. Extract the enriched logger from the Adapter Context
	reqCtx := utils.FromContext(c.Context())
	l := reqCtx.Logger

	l.Info("Handling logout request")

	// 2. Bind JSON Body
	var req dto.LogoutRequest
	if err := c.Bind().Body(&req); err != nil {
		l.Warn("Failed to parse logout request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	// 3. Validation
	if err := utils.Validate(req); err != nil {
		l.Warn("Logout request validation failed", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	// 4. Execute Use Case with separated Logger and raw business data
	// We pass the logger (with trace_id) and the token string directly
	if err := h.uc.Execute(l, req.RefreshToken); err != nil {
		// Logging of the specific failure is handled inside the Use Case logic
		return err
	}

	l.Info("User logged out successfully")

	// 5. Return 204 No Content
	return c.SendStatus(fiber.StatusNoContent)
}
