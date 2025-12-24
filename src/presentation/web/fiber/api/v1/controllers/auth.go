package controllers

import (
	"go_auth/src/application/handlers"
	"go_auth/src/domain/errors"
	"go_auth/src/presentation/web/fiber/dto"

	"github.com/gofiber/fiber/v2"
)

type AuthController struct {
	registerHandler     *handlers.RegisterHandler
	loginHandler        *handlers.LoginHandler
	logoutHandler       *handlers.LogoutHandler
	refreshTokenHandler *handlers.RefreshTokenHandler
}

func NewAuthController(
	registerHandler *handlers.RegisterHandler,
	loginHandler *handlers.LoginHandler,
	logoutHandler *handlers.LogoutHandler,
	refreshTokenHandler *handlers.RefreshTokenHandler,
) *AuthController {
	return &AuthController{
		registerHandler:     registerHandler,
		loginHandler:        loginHandler,
		logoutHandler:       logoutHandler,
		refreshTokenHandler: refreshTokenHandler,
	}
}

func (ac *AuthController) Register(c *fiber.Ctx) error {
	var req dto.RegisterRequest

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	authResp, err := ac.registerHandler.Execute(req.Email, req.Password)
	if err != nil {
		switch err {
		case errors.ErrEmailAlreadyRegistered:
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": err.Error(),
			})
		default:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
	}

	if authResp != nil {
		return c.Status(fiber.StatusCreated).JSON(authResp)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "user registered successfully",
	})
}

func (c *AuthController) Login(ctx *fiber.Ctx) error {
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

	authResp, err := c.loginHandler.Execute(
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

func (c *AuthController) Logout(ctx *fiber.Ctx) error {
	var req dto.LogoutRequest

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	return c.logoutHandler.Execute(
		req.RefreshToken,
	)
}

func (c *AuthController) RefreshToken(ctx *fiber.Ctx) error {
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
	authResp, err := c.refreshTokenHandler.Execute(req.RefreshToken, deviceID)
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
