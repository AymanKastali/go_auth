package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/application/use_cases"
	"go_auth/src/domain/errors"

	"github.com/gofiber/fiber/v2"
)

type RefreshTokenHandler struct {
	uc *use_cases.RefreshTokenUseCase
}

func NewRefreshTokenHandler(
	refreshTokenUseCase *use_cases.RefreshTokenUseCase,
) *RefreshTokenHandler {
	return &RefreshTokenHandler{uc: refreshTokenUseCase}
}

func (h *RefreshTokenHandler) Execute(ctx *fiber.Ctx) error {
	var req dto.RefreshTokenRequest // Ensure this DTO exists in your presentation layer

	deviceID := ctx.Get("X-Device-Id")
	if deviceID == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "missing device id",
		})
	}

	// 1. Parse request body
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// 2. Call the application handler
	authResp, err := h.uc.Execute(req.RefreshToken, deviceID)
	if err != nil {
		switch err {
		case errors.ErrInvalidToken:
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired refresh token",
			})
		case errors.ErrUserNotFound:
			return ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": err.Error(),
			})
		default:
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "an unexpected error occurred",
			})
		}
	}

	// 3. Map to presentation DTO and return
	// Note: Reusing LoginResponse is common since the fields (AT/RT) are the same
	response := dto.LoginResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
	}

	return ctx.Status(fiber.StatusOK).JSON(response)
}
