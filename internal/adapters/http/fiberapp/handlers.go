package fiberapp

import (
	"go_auth/internal/adapters"
	"go_auth/internal/core/application"

	"github.com/gofiber/fiber/v3"
)

type AuthHandler struct {
	registerUC     application.IRegisterUseCase
	loginUC        application.ILoginUserUseCase
	refreshUC      application.IRefreshTokenUseCase
	logoutUC       application.ILogoutUseCase
	validateAccess application.IValidateAccessUseCase
}

func NewAuthHandler(
	reg application.IRegisterUseCase,
	log application.ILoginUserUseCase,
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

// 1. Register
func (h *AuthHandler) Register(c fiber.Ctx) error {
	var req RegisterRequest
	if err := c.Bind().Body(&req); err != nil {
		return adapters.ErrBadRequest(err.Error())
	}

	if err := Validate(req); err != nil {
		return adapters.ErrBadRequest(err.Error())
	}

	// Map to Application Command
	cmd := application.RegisterUserCommand{
		Email:    req.Email,
		Password: req.Password,
	}

	user, err := h.registerUC.Execute(c.Context(), cmd)
	registerResp := RegisterUserResponse{
		UserID: user.UserID,
		Email:  user.Email,
	}

	if err != nil {
		return err
	}
	return SendCreated(c, "user registered successfully", registerResp)
}

// 2. Login
func (h *AuthHandler) Login(c fiber.Ctx) error {
	var req LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		return adapters.ErrBadRequest(err.Error())
	}

	// Validate the request fields (email, password)
	if err := Validate(req); err != nil {
		return adapters.ErrBadRequest(err.Error())
	}

	rc := GetRequestContext(c.Context())
	meta := rc.Device()

	// Build the LoginCommand using headers-derived fingerprint
	cmd := application.LoginCommand{
		Email:          req.Email,
		Password:       req.Password,
		IPAddress:      rc.IPAddress(),
		OS:             meta.OS,
		Browser:        meta.Browser,
		Model:          meta.Model,
		AcceptLanguage: rc.AcceptLanguage(),
		UserAgent:      rc.UserAgent(),
		IsMobile:       meta.IsMobile,
	}

	resp, err := h.loginUC.Execute(c.Context(), cmd)
	if err != nil {
		return err
	}
	loginResp := LoginResponse{
		AccessToken:        resp.AccessToken,
		AccessTokenExpiry:  resp.AccessTokenExpiry,
		RefreshToken:       resp.RefreshToken,
		RefreshTokenExpiry: resp.RefreshTokenExpiry,
	}

	return SendOK(c, "login successful", loginResp)
}

// 3. Refresh Token
func (h *AuthHandler) Refresh(c fiber.Ctx) error {
	var req RefreshRequest
	if err := c.Bind().Body(&req); err != nil {
		return adapters.ErrBadRequest(err.Error())
	}

	cmd := application.RefreshTokenCommand{
		RefreshToken: req.RefreshToken,
	}

	resp, err := h.refreshUC.Execute(c.Context(), cmd)
	if err != nil {
		return err
	}

	return SendOK(c, "token refreshed", resp)
}

// 4. Logout
func (h *AuthHandler) Logout(c fiber.Ctx) error {
	// 1. Retrieve IDs injected by the Protected middleware
	userID, okU := c.Locals("user_id").(string)
	sessionID, okS := c.Locals("session_id").(string)

	if !okU || !okS {
		return adapters.ErrBadRequest("missing identity context in request")
	}

	// 2. Build the command correctly
	cmd := application.LogoutCommand{
		UserID:    userID,
		SessionID: sessionID,
	}

	// 3. Execute
	if err := h.logoutUC.Execute(c.Context(), cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}
