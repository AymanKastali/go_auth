package controllers

import (
	"go_auth/src/application/handlers"

	"github.com/gofiber/fiber/v2"
)

type UserController struct {
	authUserHandler *handlers.AuthenticatedUserHandler
}

func NewUserController(
	meHandler *handlers.AuthenticatedUserHandler,
) *UserController {
	return &UserController{
		authUserHandler: meHandler,
	}
}

func (c *UserController) Me(ctx *fiber.Ctx) error {
	userID := ctx.Locals("userID")
	if userID == nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	profile, err := c.authUserHandler.GetAuthenticatedUser(userID.(string))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	if profile == nil {
		return ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "user not found",
		})
	}

	return ctx.JSON(profile)
}
