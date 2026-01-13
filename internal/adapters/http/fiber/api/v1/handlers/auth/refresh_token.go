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
	traceID, _ := c.Locals("trace_id").(string)
	if traceID == "" {
		traceID = c.Get("X-Request-ID", "refresh-flow")
	}

	// 2. TRANSPORT: Extract Device ID
	deviceID := c.Get("X-Device-ID")
	if deviceID == "" {
		// Missing required headers is a BadRequest/Unauthorized state
		return apperr.BadRequest("missing device id header", traceID, nil)
	}

	var req dto.RefreshTokenRequest

	// 3. TRANSPORT: Parse body
	if err := c.BodyParser(&req); err != nil {
		return apperr.BadRequest("invalid request payload", traceID, err)
	}

	// 4. APPLICATION: Call use case with (traceID, refreshToken, deviceID)
	// This matches the updated port signature
	authResp, err := h.uc.Execute(traceID, req.RefreshToken, deviceID)
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
