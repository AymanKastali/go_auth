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
	var req dto.RefreshTokenRequest

	// 1. TRANSPORT: Extract Device ID
	deviceID := c.Get("X-Device-ID")
	if deviceID == "" {
		return apperr.NewUnauthorizedErr("missing device id header")
	}

	// 2. TRANSPORT: Parse body
	if err := c.BodyParser(&req); err != nil {
		return apperr.NewValidationErr(err)
	}

	// 3. APPLICATION: Call use case
	authResp, err := h.uc.Execute(req.RefreshToken, deviceID)
	if err != nil {
		return err
	}

	// 4. SUCCESS: Standardized response using your utility
	return utils.OK(
		c,
		dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
		"User token refreshed successfully",
	)
}
