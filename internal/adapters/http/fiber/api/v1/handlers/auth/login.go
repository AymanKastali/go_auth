package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/fibererr"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports/use_cases"

	"github.com/gofiber/fiber/v2"
)

type LoginHandler struct {
	useCase use_cases.LoginUseCasePort
}

func NewLoginHandler(
	uc use_cases.LoginUseCasePort,
) *LoginHandler {
	return &LoginHandler{useCase: uc}
}

func (h *LoginHandler) Login(c *fiber.Ctx) error {
	var req dto.LoginRequest

	// Extract context (device info, etc.)
	ctx, err := utils.ExtractRequestContext(c)
	if err != nil {
		return utils.Failure(c, fiber.StatusBadRequest, err.Error(), "Device ID")
	}

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return utils.Failure(c, fiber.StatusBadRequest, "Invalid request body", "json")
	}

	// Call use case
	authResp, err := h.useCase.Login(
		req.Email,
		req.Password,
		ctx.DeviceID,
		ctx.DeviceName,
		ctx.UserAgent,
		ctx.IPAddress,
	)
	if err != nil {
		return fibererr.TranslateErr(c, err)
	}

	// Success response
	return utils.Success(
		c,
		fiber.StatusOK,
		dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
		"User logged in successfully",
	)
}
