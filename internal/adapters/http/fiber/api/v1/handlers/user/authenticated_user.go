package user_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports/use_cases"

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

func (h *AuthenticatedUserHandler) Execute(c *fiber.Ctx) error {
	userID := c.Locals("sub")
	if userID == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	profile, err := h.uc.GetAuthUser(userID.(string))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	if profile == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
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

	return utils.OK(c, userResponse, "User authenticated successfully")

}
