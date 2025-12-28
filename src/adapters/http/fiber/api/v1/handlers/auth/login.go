package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/adapters/http/fiber/utils"
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

func (h *LoginHandler) Login(c *fiber.Ctx) error {
	var req dto.LoginRequest

	deviceID := c.Get("X-Device-ID")
	if deviceID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "missing device id",
		})
	}

	deviceName := c.Get("X-Device-Name") // optional
	userAgent := c.Get("User-Agent")     // optional
	ipAddress := c.IP()                  // Fiber helper for client IP
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
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
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		case errors.ErrUserNotMemberOfOrganization:
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
	}

	loginResponse := dto.LoginResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
	}

	// return c.Status(fiber.StatusOK).JSON(loginResponse)

	return utils.Success(c, fiber.StatusOK, loginResponse, "User logged in successfully")
}
