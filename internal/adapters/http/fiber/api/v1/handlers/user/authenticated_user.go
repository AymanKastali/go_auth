package user_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type AuthUserHandler struct {
	uc ports.AuthUserUseCasePort
}

func NewAuthUserHandler(uc ports.AuthUserUseCasePort) *AuthUserHandler {
	return &AuthUserHandler{uc: uc}
}

func (h *AuthUserHandler) Execute(c *fiber.Ctx) error {
	// 1. Extract adapter data
	sub := c.Locals("sub")
	if sub == nil {
		return apperr.NewUnauthorizedErr("unauthorized")
	}

	userID, ok := sub.(string)
	if !ok {
		return apperr.NewInternalErr("invalid subject in context")
	}

	// 2. Call application layer
	profile, err := h.uc.Execute(userID)
	if err != nil {
		return err
	}

	if profile == nil {
		return apperr.NewNotFoundErr("user", userID)
	}

	// 3. Map domain → web DTO
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
