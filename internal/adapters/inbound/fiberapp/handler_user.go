package fiberapp

import (
	"go_auth/internal/application"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
)

// User Handler
type UserHandler struct {
	validate       *validator.Validate
	findByEmail    application.IFindUserByEmailUseCase
	getByID        application.IGetUserByIDUseCase
	getMe          application.IGetMeUseCase
	updateMe       application.IUpdateMeUseCase
	changePassword application.IChangePasswordUseCase
}

func NewUserHandler(
	validate *validator.Validate,
	findByEmail application.IFindUserByEmailUseCase,
	getByID application.IGetUserByIDUseCase,
	getMe application.IGetMeUseCase,
	updateMe application.IUpdateMeUseCase,
	changePassword application.IChangePasswordUseCase,
) *UserHandler {

	return &UserHandler{
		validate:       validate,
		findByEmail:    findByEmail,
		getByID:        getByID,
		getMe:          getMe,
		updateMe:       updateMe,
		changePassword: changePassword,
	}

}

// @Summary Find user by email
// @Description Search for a specific user using their email address
// @Tags Users
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param email query string true "User Email"
// @Success 200 {object} SuccessResponse{data=UserResponse}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/users [get]
func (h *UserHandler) FindByEmail(c fiber.Ctx) error {
	ctx := c.Context()
	email := c.Query("email")

	if email == "" {
		return SendBadRequest(c, "query parameter 'email' is required for search", nil)
	}

	user, err := h.findByEmail.Execute(ctx, email)
	if err != nil {
		return err // Assuming your error handler converts domain errors to HTTP
	}

	return SendOK(c, "user found", mapToResponse(user))
}

// @Summary Get user by ID
// @Description Retrieve a user's public profile by their unique ID
// @Tags Users
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Success 200 {object} SuccessResponse{data=UserResponse}
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /api/v1/users/{id} [get]
func (h *UserHandler) GetByID(c fiber.Ctx) error {
	ctx := c.Context()
	id := c.Params("id")

	if id == "" {
		return SendBadRequest(c, "user ID is required in path", nil)
	}

	user, err := h.getByID.Execute(ctx, id)
	if err != nil {
		return err
	}

	return SendOK(c, "user found", mapToResponse(user))
}

// @Summary Get current user
// @Description Retrieve the profile of the currently authenticated user
// @Tags Users
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Success 200 {object} SuccessResponse{data=UserResponse}
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/users/me [get]
func (h *UserHandler) GetMe(c fiber.Ctx) error {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	// 1. Extract User ID using the application helper
	// This assumes your Auth middleware has already placed the ID in the context
	userID := application.GetUserID(ctx)

	if userID.IsEmpty() {
		logger.Warn("http_get_current_unauthorized_attempt")
		return SendUnauthorized(c, "user identification missing")
	}

	// 2. Execute the Use Case
	// We pass the validated userID to the application layer
	user, err := h.getMe.Execute(ctx, userID.String())
	if err != nil {
		// Return the error to be handled by your Global Error Handler / Mapper
		return err
	}

	return SendOK(c, "current user profile fetched", mapToResponse(user))
}

// @Summary Update Current User Profile
// @Description Update the authenticated user's email
// @Tags Users
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param request body UpdateMeRequest true "Update Details"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/users/me [patch]
func (h *UserHandler) UpdateMe(c fiber.Ctx) error {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	var req UpdateMeRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	// Execute Use Case
	cmd := application.UpdateMeCommand{Email: req.Email}
	err := h.updateMe.Execute(ctx, cmd)
	if err != nil {
		// NewErrorHandler will handle domain errors like ErrUserEmailTaken
		return err
	}

	logger.Info("user_profile_updated")
	return SendNoContent(c)
}

func mapToResponse(user application.UserReadModel) UserResponse {
	return UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		RegisteredAt: user.RegisteredAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// @Summary Change Password
// @Description Update the authenticated user's password
// @Tags Users
// @Security ApiKeyAuth
// @Accept json
// @Produce json
// @Param request body ChangePasswordRequest true "Password Details"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/users/me/password [put]
func (h *UserHandler) ChangePassword(c fiber.Ctx) error {
	ctx := c.Context()
	var req ChangePasswordRequest

	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body", nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := application.ChangePasswordCommand{
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}

	if err := h.changePassword.Execute(ctx, cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}
