package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils" // Keep success util
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports/use_cases"

	"github.com/gofiber/fiber/v2"
)

type RefreshTokenHandler struct {
	useCase use_cases.RefreshTokenUseCasePort
}

func NewRefreshTokenHandler(uc use_cases.RefreshTokenUseCasePort) *RefreshTokenHandler {
	return &RefreshTokenHandler{useCase: uc}
}

func (h *RefreshTokenHandler) Execute(c *fiber.Ctx) error {
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
	authResp, err := h.useCase.RefreshToken(req.RefreshToken, deviceID)
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
