package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type refreshTokenHandler struct {
	uc ports.RefreshTokenUseCasePort
}

var _ interfaces.IRefreshTokenHandler = (*refreshTokenHandler)(nil)

func NewRefreshTokenHandler(
	uc ports.RefreshTokenUseCasePort,
) interfaces.IRefreshTokenHandler {
	return &refreshTokenHandler{uc: uc}
}

func (h *refreshTokenHandler) Execute(c *fiber.Ctx) error {
	// 1. Extract TraceID (Necessary for the AppError factories)
	ctx := utils.GetContext(c)

	var req dto.RefreshTokenRequest

	// 3. TRANSPORT: Parse body
	if err := c.BodyParser(&req); err != nil {
		return apperr.BadRequest("invalid request payload", ctx.RequestID, err)
	}

	// 4. APPLICATION: Call use case with (requestID, refreshToken, deviceID)
	// This matches the updated port signature
	authResp, err := h.uc.Execute(ctx.RequestID, req.RefreshToken, ctx.DeviceID)
	if err != nil {
		// Bubbles up apperr.Unauthorized, apperr.Conflict (reuse detection), etc.
		return err
	}

	// 5. SUCCESS: Standardized response
	return utils.OK(
		c,
		dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
		"User token refreshed successfully",
	)
}
