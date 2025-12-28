package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/application/use_cases"
	"go_auth/src/domain/errors"

	"github.com/gofiber/fiber/v2"
)

type LoginHandler struct {
	uc *use_cases.LoginUseCase
}

func NewLoginHandler(
	loginUseCase *use_cases.LoginUseCase,
) *LoginHandler {
	return &LoginHandler{uc: loginUseCase}
}

func (h *LoginHandler) Execute(ctx *fiber.Ctx) error {
	var req dto.LoginRequest

	deviceID := ctx.Get("X-Device-Id")
	if deviceID == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "missing device id",
		})
	}

	deviceName := ctx.Get("X-Device-Name") // optional
	userAgent := ctx.Get("User-Agent")     // optional
	ipAddress := ctx.IP()                  // Fiber helper for client IP

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	authResp, err := h.uc.Execute(
		req.Email,
		req.Password,
		deviceID,
		deviceName,
		userAgent,
		ipAddress,
	)
	if err != nil {
		switch err {
		case errors.ErrInvalidCredentials:
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		case errors.ErrUserNotMemberOfOrganization:
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		default:
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
	}

	loginResponse := dto.LoginResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
	}

	return ctx.Status(fiber.StatusOK).JSON(loginResponse)
}
