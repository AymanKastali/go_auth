package users

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v3"
)

type AuthUserHandler struct {
	uc ports.IAuthUserUseCase
}

func NewAuthUserHandler(uc ports.IAuthUserUseCase) *AuthUserHandler {
	return &AuthUserHandler{uc: uc}
}

// Execute handles the retrieval of the current authenticated user's profile.
// @Summary      Get Current User
// @Description  Retrieves detailed profile information for the user currently logged in.
// @Tags         user
// @Produce      json
// @Success      200      {object}  dto.SuccessResponse{data=dto.UserResponse} "Profile retrieved successfully"
// @Failure      401      {object}  dto.ErrorResponse "Unauthorized - Session missing or invalid"
// @Failure      404      {object}  dto.ErrorResponse "User not found"
// @Failure      500      {object}  dto.ErrorResponse "Internal server error"
// @Router       /user/me [get]
func (h *AuthUserHandler) Execute(c fiber.Ctx) error {
	// 1. Extract the AuthContext (Injected by JWTMiddleware)
	auth, ok := utils.AuthFromContext(c.Context())
	if !ok {
		// Use the base request context logger if auth is unexpectedly missing
		utils.FromContext(c.Context()).Logger.Error("identity missing from context in protected route")
		return apperr.Unauthorized("identity not found in context", nil)
	}

	// This logger is already enriched with trace_id, user_id, fingerprint, and ip
	l := auth.Logger

	l.Info("Retrieving authenticated user profile")

	// 2. Execute Use Case with explicit Logger and UserID (No Context)
	profile, err := h.uc.Execute(l, auth.UserID)
	if err != nil {
		// Specific warning logging is handled inside the Use Case or Global Error Handler
		return err
	}

	l.Debug("User profile retrieved successfully")

	// 3. Map Domain Profile to HTTP Response DTO
	data := dto.UserResponse{
		ID:        profile.ID,
		Email:     profile.Email,
		Status:    profile.Status,
		Roles:     profile.Roles,
		CreatedAt: profile.CreatedAt,
		UpdatedAt: profile.UpdatedAt,
	}
	resp := dto.SuccessResponse{Message: "User profile retrieved successfully", Data: data}

	// 4. Return standardized success envelope
	return c.Status(fiber.StatusOK).JSON(resp)
}
