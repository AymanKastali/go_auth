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
	// 1. Extract TraceID (Required by the new AppError system)
	traceID, _ := c.Locals("trace_id").(string)
	if traceID == "" {
		traceID = "system-handler"
	}

	// 2. Extract UserID from Locals (Set by JWTMiddleware)
	sub := c.Locals("sub")
	if sub == nil {
		return apperr.Unauthorized("unauthorized: session context missing", traceID, nil)
	}

	userID, ok := sub.(string)
	if !ok {
		return apperr.Internal("invalid subject type in context", traceID, nil)
	}

	// 3. Call application layer with BOTH arguments: (traceID, userID)
	profile, err := h.uc.Execute(traceID, userID)
	if err != nil {
		// Use Case already returns a properly wrapped apperr.AppError
		return err
	}

	// Note: We removed the profile == nil check here because the Use Case
	// now correctly returns apperr.NotFound if the user doesn't exist.

	// 4. Map application DTO → web response DTO
	userResponse := dto.UserResponse{
		ID:        profile.ID,
		Email:     profile.Email,
		Status:    profile.Status,
		Roles:     profile.Roles, // Assuming slice of strings
		CreatedAt: profile.CreatedAt,
		UpdatedAt: profile.UpdatedAt,
	}

	return utils.OK(c, userResponse, "User profile retrieved successfully")
}
