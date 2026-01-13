package user_handlers

import (
	"errors"
	"fmt" // Added for printing
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
	fmt.Printf("--- Handling AuthUser Request: %s %s ---\n", c.Method(), c.Path())

	// 1. Extract adapter data
	sub := c.Locals("sub")
	if sub == nil {
		fmt.Println("[Error] Sub not found in context locals")
		return apperr.Unauthorized(errors.New("unauthorized"))
	}

	userID, ok := sub.(string)
	if !ok {
		fmt.Printf("[Error] Sub exists but type assertion failed: %v\n", sub)
		return apperr.Internal(errors.New("invalid subject in context"))
	}

	fmt.Printf("[Info] Extracted UserID: %s\n", userID)

	// 2. Call application layer
	profile, err := h.uc.Execute(userID)
	if err != nil {
		fmt.Printf("[Error] UseCase Execution Failed: %v\n", err)
		return err
	}

	if profile == nil {
		fmt.Println("[Warn] Profile returned is nil")
		return apperr.NotFound(errors.New("user not found"))
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

	fmt.Printf("[Success] User %s profile mapped and ready for response\n", userResponse.Email)
	return utils.OK(c, userResponse, "User authenticated successfully")
}
