package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/application/ports/use_cases"
	"go_auth/src/domain/errors"

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

func (h *LoginHandler) Login(ctx *fiber.Ctx) error {
	var req dto.LoginRequest

	deviceID := ctx.Get("X-Device-ID")
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

	authResp, err := h.useCase.Login(
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
