package fiberapp

import (
	"go_auth/internal/application"
	"go_auth/internal/application/command"
	"go_auth/internal/application/query"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
)

// UserController handles user-related HTTP endpoints.
type UserController struct {
	validate       *validator.Validate
	findByEmail    query.IFindUserByEmailHandler
	getByID        query.IGetUserByIDHandler
	getMe          query.IGetMeHandler
	updateMe       command.IUpdateMeHandler
	changePassword command.IChangePasswordHandler
}

func NewUserController(
	validate *validator.Validate,
	findByEmail query.IFindUserByEmailHandler,
	getByID query.IGetUserByIDHandler,
	getMe query.IGetMeHandler,
	updateMe command.IUpdateMeHandler,
	changePassword command.IChangePasswordHandler,
) *UserController {

	return &UserController{
		validate:       validate,
		findByEmail:    findByEmail,
		getByID:        getByID,
		getMe:          getMe,
		updateMe:       updateMe,
		changePassword: changePassword,
	}

}

func (h *UserController) RegisterRoutes(users fiber.Router) {
	users.Get("/me", h.GetMe)
	users.Patch("/me", h.UpdateMe)
	users.Put("/me/password", h.ChangePassword)
	users.Get("", h.FindByEmail)
	users.Get("/:id", h.GetByID)
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
func (h *UserController) FindByEmail(c fiber.Ctx) error {
	ctx := c.Context()
	email := c.Query("email")

	if email == "" {
		return SendBadRequest(c, "query parameter 'email' is required for search", nil)
	}

	user, err := h.findByEmail.Handle(ctx, email)
	if err != nil {
		return err
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
func (h *UserController) GetByID(c fiber.Ctx) error {
	ctx := c.Context()
	id := c.Params("id")

	if id == "" {
		return SendBadRequest(c, "user ID is required in path", nil)
	}

	user, err := h.getByID.Handle(ctx, id)
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
func (h *UserController) GetMe(c fiber.Ctx) error {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	userID := application.GetUserID(ctx)

	if userID.IsEmpty() {
		logger.Warn("http_get_current_unauthorized_attempt")
		return SendUnauthorized(c, "user identification missing")
	}

	user, err := h.getMe.Handle(ctx, userID.String())
	if err != nil {
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
func (h *UserController) UpdateMe(c fiber.Ctx) error {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	var req UpdateMeRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := command.UpdateMeCommand{Email: req.Email}
	err := h.updateMe.Handle(ctx, cmd)
	if err != nil {
		return err
	}

	logger.Info("user_profile_updated")
	return SendNoContent(c)
}

func mapToResponse(user application.UserReadModel) UserResponse {
	return UserResponse{
		ID:           user.ID,
		Email:        user.Email,
		RegisteredAt: user.RegisteredAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:    user.UpdatedAt.Format("2006-01-02T15:04:05Z"),
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
func (h *UserController) ChangePassword(c fiber.Ctx) error {
	ctx := c.Context()
	var req ChangePasswordRequest

	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body", nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := command.ChangePasswordCommand{
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}

	if err := h.changePassword.Handle(ctx, cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}
