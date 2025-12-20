package controllers

import (
	"go_auth/src/application/handlers"
	"go_auth/src/presentation/web/fiber/dto"

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

	userResponse := dto.UserResponse{
		ID:        profile.ID,
		Email:     profile.Email,
		Status:    string(profile.Status),
		Roles:     make([]string, len(profile.Roles)),
		CreatedAt: profile.CreatedAt,
		UpdatedAt: profile.UpdatedAt,
	}

	for i, role := range profile.Roles {
		userResponse.Roles[i] = string(role)
	}

	return ctx.JSON(userResponse)
}
