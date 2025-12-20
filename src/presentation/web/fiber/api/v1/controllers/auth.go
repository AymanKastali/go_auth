package controllers

import (
	"go_auth/src/application/handlers"
	"go_auth/src/domain/errors"
	"go_auth/src/presentation/web/fiber/dto"

	"github.com/gofiber/fiber/v2"
)

type AuthController struct {
	registerHandler *handlers.RegisterHandler
	loginHandler    *handlers.LoginHandler
}

func NewAuthController(
	registerHandler *handlers.RegisterHandler,
	loginHandler *handlers.LoginHandler,
) *AuthController {
	return &AuthController{
		registerHandler: registerHandler,
		loginHandler:    loginHandler,
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

	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	authResp, err := c.loginHandler.Execute(req.Email, req.Password)
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
