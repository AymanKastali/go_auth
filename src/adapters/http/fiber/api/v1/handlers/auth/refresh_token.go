package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/application/ports/use_cases"
	"go_auth/src/domain/errors"

	"github.com/gofiber/fiber/v2"
)

type RefreshTokenHandler struct {
	useCase use_cases.RefreshTokenUseCasePort
}

func NewRefreshTokenHandler(
	uc use_cases.RefreshTokenUseCasePort,
) *RefreshTokenHandler {
	return &RefreshTokenHandler{useCase: uc}
}

func (h *RefreshTokenHandler) Execute(ctx *fiber.Ctx) error {
	var req dto.RefreshTokenRequest // Ensure this DTO exists in your presentation layer

	deviceID := ctx.Get("X-Device-ID")
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
	authResp, err := h.useCase.RefreshToken(req.RefreshToken, deviceID)
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
