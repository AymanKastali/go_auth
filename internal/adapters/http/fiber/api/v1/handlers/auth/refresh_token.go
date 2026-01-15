package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type refreshTokenHandler struct {
	uc ports.IRefreshTokenUseCase
}

func NewRefreshTokenHandler(uc ports.IRefreshTokenUseCase) *refreshTokenHandler {
	return &refreshTokenHandler{uc: uc}
}

func (h *refreshTokenHandler) Execute(c *fiber.Ctx) error {
	// 1. Context Acquisition
	ctx := utils.GetContext(c)
	traceID := ctx.RequestID

	var req dto.RefreshTokenRequest

	// 2. Protocol Layer: Syntax Check (HTTP 400)
	if err := c.BodyParser(&req); err != nil {
		// Handled by the HTTP Protocol layer, core remains untouched
		return http.NewBadRequest(err)
	}

	// 3. Application Layer: Schema Validation (HTTP 422)
	if err := utils.Validate(req); err != nil {
		return http.NewBadRequest(err)
	}

	// 4. Core Execution: Rotation Orchestration
	// The UC handles JWT signature verification, blacklisting, and rotation
	authResp, err := h.uc.Execute(
		traceID,
		req.RefreshToken,
		ctx.DeviceID,
	)
	if err != nil {
		// Standardized return of apperr.AppError (e.g., Conflict, Unauthorized)
		return err
	}

	// 5. Success Presentation
	return utils.OK(
		c,
		dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
		"tokens rotated successfully",
	)
}
