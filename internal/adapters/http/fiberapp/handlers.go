package fiberapp

import (
	"go_auth/internal/core/application"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

type AuthHandler struct {
	registerUC     application.IRegisterUseCase
	loginUC        application.ILoginUseCase
	refreshUC      application.IRefreshTokenUseCase
	logoutUC       application.ILogoutUseCase
	validateAccess application.IValidateAccessUseCase
}

// ... NewAuthHandler constructor ...
func NewAuthHandler(
	reg application.IRegisterUseCase,
	log application.ILoginUseCase,
	ref application.IRefreshTokenUseCase,
	out application.ILogoutUseCase,
	val application.IValidateAccessUseCase,
) *AuthHandler {

	return &AuthHandler{
		registerUC:     reg,
		loginUC:        log,
		refreshUC:      ref,
		logoutUC:       out,
		validateAccess: val,
	}

}

// @Summary Register a new user
// @Description Create a user account with email and password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body RegisterRequest true "Registration Details"
// @Success 201 {object} SuccessResponse{data=RegisterUserResponse}
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/auth/register [post]
func (h *AuthHandler) Register(c fiber.Ctx) error {
	logger := application.GetLogger(c.Context())

	var req RegisterRequest
	if err := c.Bind().Body(&req); err != nil {
		logger.Warn("register_binding_failed", slog.Any("error", err))
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := Validate(req); err != nil {
		logger.Warn("register_validation_failed", slog.Any("error", err))
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := application.RegisterUserCommand{
		Email:    req.Email,
		Password: req.Password,
	}

	user, err := h.registerUC.Execute(c.Context(), cmd)
	if err != nil {
		// UseCase already logged the specific reason, just return
		return err
	}

	logger.Info("http_register_success", slog.String("email", req.Email))
	return SendCreated(c, "user registered successfully", RegisterUserResponse{
		UserID: user.UserID,
		Email:  user.Email,
	})
}

// @Summary User Login
// @Description Authenticate user and return tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login Credentials"
// @Success 200 {object} SuccessResponse{data=LoginResponse}
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) Login(c fiber.Ctx) error {
	logger := application.GetLogger(c.Context())

	var req LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		logger.Warn("login_binding_failed", slog.Any("error", err))
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := Validate(req); err != nil {
		logger.Warn("login_validation_failed", slog.Any("error", err))
		return SendBadRequest(c, err.Error(), nil)
	}

	identity := application.GetIdentity(c.Context())

	cmd := application.LoginCommand{
		Email:          req.Email,
		Password:       req.Password,
		IPAddress:      identity.IPAddress(),
		OS:             identity.OS(),
		Browser:        identity.Browser(),
		Model:          identity.Model(),
		AcceptLanguage: identity.Language(),
		UserAgent:      identity.UserAgent(),
		IsMobile:       identity.IsMobile(),
	}

	resp, err := h.loginUC.Execute(c.Context(), cmd)
	if err != nil {
		return err
	}

	logger.Info("http_login_success", slog.String("email", req.Email))
	return SendOK(c, "login successful", LoginResponse{
		AccessToken:        resp.AccessToken,
		AccessTokenExpiry:  resp.AccessTokenExpiry,
		RefreshToken:       resp.RefreshToken,
		RefreshTokenExpiry: resp.RefreshTokenExpiry,
	})
}

// @Summary Refresh Access Token
// @Description Exchange a valid refresh token for a new access token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Refresh Token"
// @Success 200 {object} SuccessResponse{data=LoginResponse}
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) Refresh(c fiber.Ctx) error {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	var req RefreshRequest
	if err := c.Bind().Body(&req); err != nil {
		logger.Warn("refresh_binding_failed", slog.Any("error", err))
		return SendBadRequest(c, err.Error(), nil)
	}

	userID := application.GetUserID(ctx)
	fingerprint := application.GetIdentity(ctx).Fingerprint()

	// Log that a refresh is being attempted for this user
	logger.Debug("http_refresh_attempt",
		slog.String("user_id", userID.String()),
		slog.String("fingerprint", fingerprint.String()),
	)

	cmd := application.RefreshTokenCommand{
		RefreshToken: req.RefreshToken,
		UserID:       userID.String(),
		Fingerprint:  fingerprint.String(),
	}

	resp, err := h.refreshUC.Execute(ctx, cmd)
	if err != nil {
		return err
	}

	logger.Info("http_refresh_success", slog.String("user_id", userID.String()))
	return SendOK(c, "token refreshed", resp)
}

// @Summary Logout
// @Description Revoke the current session
// @Tags Auth
// @Security ApiKeyAuth
// @Success 204 "No Content"
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(c fiber.Ctx) error {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	if !application.IsAuthenticated(ctx) {
		logger.Warn("logout_attempt_unauthenticated")
		return SendBadRequest(c, "missing identity context in request", nil)
	}

	userID := application.GetUserID(ctx)
	sessionID := application.GetSessionID(ctx)

	cmd := application.LogoutCommand{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
	}

	if err := h.logoutUC.Execute(ctx, cmd); err != nil {
		return err
	}

	logger.Info("http_logout_success",
		slog.String("user_id", userID.String()),
		slog.String("session_id", sessionID.String()),
	)
	return SendNoContent(c)
}

// User Handler

type UserHandler struct {
	findByEmail application.IFindUserByEmail
	getByID     application.IGetUserByID
	getCurrent  application.IGetCurrentUser
}

// ... NewAuthHandler constructor ...
func UewUserHandler(
	findByEmail application.IFindUserByEmail,
	getByID application.IGetUserByID,
	getCurrent application.IGetCurrentUser,
) *UserHandler {

	return &UserHandler{
		findByEmail: findByEmail,
		getByID:     getByID,
		getCurrent:  getCurrent,
	}

}

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
func (h *UserHandler) GetCurrent(c fiber.Ctx) error {
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
	user, err := h.getCurrent.Execute(ctx, userID.String())
	if err != nil {
		// Return the error to be handled by your Global Error Handler / Mapper
		return err
	}

	return SendOK(c, "current user profile fetched", mapToResponse(user))
}

func mapToResponse(user application.UserResponse) UserResponse {
	return UserResponse{
		ID:    user.ID,
		Email: user.Email,
	}
}
