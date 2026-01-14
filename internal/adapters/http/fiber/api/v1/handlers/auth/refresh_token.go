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
	// 1. Extract context (Contains RequestID, DeviceID, etc.)
	ctx := utils.GetContext(c)
	requestID := ctx.RequestID

	var req dto.RefreshTokenRequest

	// 2. TRANSPORT: Parse request body
	if err := c.BodyParser(&req); err != nil {
		// KindInvalid: Maps to 400 Bad Request
		return apperr.Invalid("invalid request payload format", requestID, err)
	}

	// 3. Structural Validation
	// Checks if the RefreshToken string is actually provided in the body
	if err := utils.Validate(req); err != nil {
		return apperr.Invalid("validation failed: refresh token is required", requestID, err)
	}

	// 4. APPLICATION: Orchestrate the token rotation
	// This will check JWT validity, device binding, and reuse detection (revocation)
	authResp, err := h.uc.Execute(requestID, req.RefreshToken, ctx.DeviceID)
	if err != nil {
		// Propagates KindUnauthenticated (401), KindConflict (409), etc.
		return err
	}

	// 5. SUCCESS: Standardized Auth Response
	return utils.OK(
		c,
		dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
		"Tokens rotated successfully",
	)
}
