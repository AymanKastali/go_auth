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

	if err := h.registerUC.Execute(c.Context(), cmd); err != nil {
		return err
	}

	return SendNoContent(c)
}

// 2. Login
func (h *AuthHandler) Login(c fiber.Ctx) error {
	var req LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		return adapters.ErrBadRequest(err.Error())
	}

	if err := Validate(req); err != nil {
		return adapters.ErrBadRequest(err.Error())
	}

	// Map to Application Command
	cmd := application.LoginCommand{
		Email:       req.Email,
		Password:    req.Password,
		Fingerprint: req.Fingerprint,
		UserAgent:   c.Get("User-Agent"),
		IPAddress:   c.IP(),
	}

	resp, err := h.loginUC.Execute(c.Context(), cmd)
	if err != nil {
		return err
	}

	return SendOK(c, "login successful", resp)
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
