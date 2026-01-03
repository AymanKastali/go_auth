package auth_handlers

import (
	"go_auth/internal/adapters/adaptererr"
	"go_auth/internal/adapters/http/fiber/dto"
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
		// Use the same standardized response even for simple transport checks
		status, payload := adaptererr.Translate(apperr.ErrUnauthorized)
		return c.Status(status).JSON(payload)
	}

	// 2. TRANSPORT: Parse body
	if err := c.BodyParser(&req); err != nil {
		// We can pass a specific apperr for bad input
		status, payload := adaptererr.Translate(apperr.MapDomain(err))
		return c.Status(status).JSON(payload)
	}

	// 3. APPLICATION: Call use case
	authResp, err := h.useCase.RefreshToken(req.RefreshToken, deviceID)
	if err != nil {
		// The handler no longer cares if it's a 401, 403, or 500
		status, payload := adaptererr.Translate(err)
		return c.Status(status).JSON(payload)
	}

	// 4. SUCCESS: Standardized response
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success": true,
		"message": "User token refreshed successfully",
		"data": dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
	})
}
