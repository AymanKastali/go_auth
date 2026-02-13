package fiberapp

import (
	"go_auth/internal/application"
	"go_auth/internal/application/command"
	"go_auth/internal/application/query"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
)

type AuthController struct {
	validate          *validator.Validate
	register          command.IRegisterHandler
	login             command.ILoginHandler
	refresh           command.IRefreshTokenHandler
	logout            command.ILogoutHandler
	validateAccess    query.IValidateAccessHandler
	forgotPassword    command.IForgotPasswordHandler
	resetPassword     command.IResetPasswordHandler
	confirmActivation command.IConfirmActivationHandler
	resendActivation  command.IResendActivationHandler
	authGuard         fiber.Handler
}

func NewAuthController(
	validate *validator.Validate,
	reg command.IRegisterHandler,
	log command.ILoginHandler,
	ref command.IRefreshTokenHandler,
	out command.ILogoutHandler,
	val query.IValidateAccessHandler,
	forgotPassword command.IForgotPasswordHandler,
	resetPassword command.IResetPasswordHandler,
	confirmActivation command.IConfirmActivationHandler,
	resendActivation command.IResendActivationHandler,
	authGuard fiber.Handler,
) *AuthController {

	return &AuthController{
		validate:          validate,
		register:          reg,
		login:             log,
		refresh:           ref,
		logout:            out,
		validateAccess:    val,
		forgotPassword:    forgotPassword,
		resetPassword:     resetPassword,
		confirmActivation: confirmActivation,
		resendActivation:  resendActivation,
		authGuard:         authGuard,
	}

}

func NewValidator() *validator.Validate {
	return validator.New()
}

func (h *AuthController) RegisterRoutes(router fiber.Router) {
	router.Post("/register", h.Register)
	router.Post("/login", h.Login)
	router.Post("/refresh", h.Refresh)
	router.Post("/activate", h.ConfirmActivation)
	router.Post("/resend-activation", h.ResendActivation)
	router.Post("/validate", h.ValidateToken)
	router.Post("/logout", h.authGuard, h.Logout)
	router.Post("/reset-password", h.ResetPassword)
	router.Post("/forgot-password", h.ForgotPassword)
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
func (h *AuthController) Register(c fiber.Ctx) error {
	var req RegisterRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := command.RegisterUserCommand{
		Email:    req.Email,
		Password: req.Password,
	}

	user, err := h.register.Handle(c.Context(), cmd)
	if err != nil {
		return err
	}

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
func (h *AuthController) Login(c fiber.Ctx) error {
	var req LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	identity := application.GetIdentity(c.Context())

	cmd := command.LoginCommand{
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

	resp, err := h.login.Handle(c.Context(), cmd)
	if err != nil {
		return err
	}

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
func (h *AuthController) Refresh(c fiber.Ctx) error {
	ctx := c.Context()

	var req RefreshRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	userID := application.GetUserID(ctx)
	fingerprint := application.GetIdentity(ctx).Fingerprint()

	cmd := command.RefreshTokenCommand{
		RefreshToken: req.RefreshToken,
		UserID:       userID.String(),
		Fingerprint:  fingerprint.String(),
	}

	resp, err := h.refresh.Handle(ctx, cmd)
	if err != nil {
		return err
	}

	return SendOK(c, "token refreshed", resp)
}

// @Summary Logout
// @Description Revoke the current session
// @Tags Auth
// @Security ApiKeyAuth
// @Success 204 "No Content"
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/logout [post]
func (h *AuthController) Logout(c fiber.Ctx) error {
	ctx := c.Context()

	if !application.IsAuthenticated(ctx) {
		return SendBadRequest(c, "missing identity context in request", nil)
	}

	userID := application.GetUserID(ctx)
	sessionID := application.GetSessionID(ctx)

	cmd := command.LogoutCommand{
		UserID:    userID.String(),
		SessionID: sessionID.String(),
	}

	if err := h.logout.Handle(ctx, cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}

func (h *AuthController) ForgotPassword(c fiber.Ctx) error {
	var req ForgotPasswordRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body", nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := command.ForgotPasswordCommand{Email: req.Email}

	if err := h.forgotPassword.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendOK(c, "If an account exists with that email, a reset link has been sent.", nil)
}

func (h *AuthController) ResetPassword(c fiber.Ctx) error {
	ctx := c.Context()
	var req ResetPasswordRequest

	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body", nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := command.ResetPasswordCommand{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	}

	if err := h.resetPassword.Handle(ctx, cmd); err != nil {
		return err
	}

	return SendOK(c, "Password has been reset successfully. You can now log in with your new credentials.", nil)
}

// @Summary Confirm account activation
// @Description Activate a user account using the activation token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ConfirmActivationRequest true "Activation Token"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/activate [post]
func (h *AuthController) ConfirmActivation(c fiber.Ctx) error {
	var req ConfirmActivationRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body", nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := command.ConfirmActivationCommand{
		Token: req.Token,
	}

	if err := h.confirmActivation.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendOK(c, "Account has been activated successfully. You can now log in.", nil)
}

// @Summary Resend activation email
// @Description Resend the activation email to the user
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ResendActivationRequest true "Email Address"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/auth/resend-activation [post]
func (h *AuthController) ResendActivation(c fiber.Ctx) error {
	var req ResendActivationRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body", nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	cmd := command.ResendActivationCommand{
		Email: req.Email,
	}

	if err := h.resendActivation.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendOK(c, "If your account requires activation, a new activation link has been sent.", nil)
}

// @Summary Validate access token
// @Description Validates an access token and returns the associated user info (service-to-service)
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ValidateTokenRequest true "Token"
// @Success 200 {object} SuccessResponse{data=ValidateTokenResponse}
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/validate [post]
func (h *AuthController) ValidateToken(c fiber.Ctx) error {
	var req ValidateTokenRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error(), nil)
	}

	q := query.ValidateAccessQuery{
		AccessToken:        req.AccessToken,
		IncludePermissions: true,
	}

	access, err := h.validateAccess.Handle(c.Context(), q)
	if err != nil {
		return err
	}

	return SendOK(c, "token is valid", ValidateTokenResponse{
		UserID:      access.UserID,
		SessionID:   access.SessionID,
		Roles:       access.Roles,
		Permissions: access.Permissions,
	})
}
