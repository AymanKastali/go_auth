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
// @Success 201 {object} DataResponse{data=RegisterUserResponse}
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/auth/register [post]
func (h *AuthController) Register(c fiber.Ctx) error {
	var req RegisterRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.RegisterUserCommand{
		Email:    req.Email,
		Password: req.Password,
	}

	user, err := h.register.Handle(c.Context(), cmd)
	if err != nil {
		return err
	}

	return SendCreated(c, RegisterUserResponse{
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
// @Success 200 {object} DataResponse{data=LoginResponse}
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/login [post]
func (h *AuthController) Login(c fiber.Ctx) error {
	var req LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
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

	return SendOK(c, LoginResponse{
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
// @Success 200 {object} DataResponse{data=LoginResponse}
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/refresh [post]
func (h *AuthController) Refresh(c fiber.Ctx) error {
	ctx := c.Context()

	var req RefreshRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error())
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

	return SendOK(c, resp)
}

// @Summary Logout
// @Description Revoke the current session
// @Tags Auth
// @Security AccessToken
// @Success 204 "No Content"
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/logout [post]
func (h *AuthController) Logout(c fiber.Ctx) error {
	ctx := c.Context()

	if !application.IsAuthenticated(ctx) {
		return SendBadRequest(c, "missing identity context in request")
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

// @Summary Forgot password
// @Description Request a password reset link by email
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "Email Address"
// @Success 200 {object} MessageResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/auth/forgot-password [post]
func (h *AuthController) ForgotPassword(c fiber.Ctx) error {
	var req ForgotPasswordRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body")
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.ForgotPasswordCommand{Email: req.Email}

	if err := h.forgotPassword.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendMessage(c, "If an account exists with that email, a reset link has been sent.")
}

// @Summary Reset password
// @Description Reset the user's password using a valid reset token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Reset Details"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/auth/reset-password [post]
func (h *AuthController) ResetPassword(c fiber.Ctx) error {
	ctx := c.Context()
	var req ResetPasswordRequest

	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body")
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.ResetPasswordCommand{
		Token:       req.Token,
		NewPassword: req.NewPassword,
	}

	if err := h.resetPassword.Handle(ctx, cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}

// @Summary Confirm account activation
// @Description Activate a user account using the activation token
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ConfirmActivationRequest true "Activation Token"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/activate [post]
func (h *AuthController) ConfirmActivation(c fiber.Ctx) error {
	var req ConfirmActivationRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body")
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.ConfirmActivationCommand{
		Token: req.Token,
	}

	if err := h.confirmActivation.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}

// @Summary Resend activation email
// @Description Resend the activation email to the user
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ResendActivationRequest true "Email Address"
// @Success 200 {object} MessageResponse
// @Failure 400 {object} ErrorResponse
// @Router /api/v1/auth/resend-activation [post]
func (h *AuthController) ResendActivation(c fiber.Ctx) error {
	var req ResendActivationRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, "invalid request body")
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	cmd := command.ResendActivationCommand{
		Email: req.Email,
	}

	if err := h.resendActivation.Handle(c.Context(), cmd); err != nil {
		return err
	}

	return SendMessage(c, "If your account requires activation, a new activation link has been sent.")
}

// @Summary Validate access token
// @Description Validates an access token and returns the associated user info (service-to-service)
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body ValidateTokenRequest true "Token"
// @Success 200 {object} DataResponse{data=ValidateTokenResponse}
// @Failure 401 {object} ErrorResponse
// @Router /api/v1/auth/validate [post]
func (h *AuthController) ValidateToken(c fiber.Ctx) error {
	var req ValidateTokenRequest
	if err := c.Bind().Body(&req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	if err := h.validate.Struct(req); err != nil {
		return SendBadRequest(c, err.Error())
	}

	q := query.ValidateAccessQuery{
		AccessToken:        req.AccessToken,
		IncludePermissions: true,
	}

	access, err := h.validateAccess.Handle(c.Context(), q)
	if err != nil {
		return err
	}

	return SendOK(c, ValidateTokenResponse{
		UserID:      access.UserID,
		SessionID:   access.SessionID,
		Roles:       access.Roles,
		Permissions: access.Permissions,
	})
}
