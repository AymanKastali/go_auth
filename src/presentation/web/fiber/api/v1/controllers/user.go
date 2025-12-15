package controllers

import (
	usecases "go_auth/src/application/use_cases"

	"github.com/gofiber/fiber/v2"
)

type UserController struct {
	UserUseCase *usecases.UserUseCase
}

func NewUserController(uc *usecases.UserUseCase) *UserController {
	return &UserController{
		UserUseCase: uc,
	}
}

// GET /api/v1/users/me
func (c *UserController) Me(ctx *fiber.Ctx) error {
	userID := ctx.Locals("userID")
	if userID == nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	profile, err := c.UserUseCase.GetAuthenticatedUser(userID.(string))
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
