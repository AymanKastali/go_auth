package user_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/application/ports/use_cases"

	"github.com/gofiber/fiber/v2"
)

type AuthenticatedUserHandler struct {
	uc use_cases.AuthenticatedUserUseCasePort
}

func NewAuthenticatedUserHandler(
	authenticatedUserUseCase use_cases.AuthenticatedUserUseCasePort,
) *AuthenticatedUserHandler {
	return &AuthenticatedUserHandler{
		uc: authenticatedUserUseCase,
	}
}

func (h *AuthenticatedUserHandler) Execute(ctx *fiber.Ctx) error {
	userId := ctx.Locals("sub")
	if userId == nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	profile, err := h.uc.Execute(userId.(string))
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
