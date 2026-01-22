package users

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

type AuthUserHandler struct {
	uc ports.IAuthUserUseCase
}

func NewAuthUserHandler(uc ports.IAuthUserUseCase) *AuthUserHandler {
	return &AuthUserHandler{uc: uc}
}

// @Summary  Get Current User
// @Tags     user
// @Produce  json
// @Success  200      {object}  interface{}
// @Failure  401      {string}  string "Unauthorized"
// @Router   /user/me [get]
func (h *AuthUserHandler) Execute(c fiber.Ctx) error {
	reqCtx := utils.ReqCtx(c)
	l := reqCtx.Logger

	auth, ok := utils.AuthCtx(c)
	if !ok {
		l.Error("identity missing from context in protected route")
		return apperr.Unauthorized("identity not found in context", nil)
	}

	l.Info("Retrieving authenticated user profile", slog.String("user_id", auth.UserID))

	profile, err := h.uc.Execute(
		c.Context(),
		auth.UserID,
	)
	if err != nil {
		l.Warn("Failed to retrieve user profile",
			slog.String("user_id", auth.UserID),
			slog.Any("error", err),
		)
		return err
	}

	userResponse := dto.UserResponse{
		ID:        profile.ID,
		Email:     profile.Email,
		Status:    profile.Status,
		Roles:     profile.Roles,
		CreatedAt: profile.CreatedAt,
		UpdatedAt: profile.UpdatedAt,
	}

	l.Debug("User profile retrieved successfully", slog.String("user_id", auth.UserID))

	return utils.OK(c, userResponse, "User profile retrieved successfully")
}
