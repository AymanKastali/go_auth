package fiberapp

import (
	"go_auth/internal/adapters"
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

// 1. Register
func (h *AuthHandler) Register(c fiber.Ctx) error {
	logger := application.GetLogger(c.Context())

	var req RegisterRequest
	if err := c.Bind().Body(&req); err != nil {
		logger.Warn("register_binding_failed", slog.Any("error", err))
		return adapters.ErrBadRequest(err.Error())
	}

	if err := Validate(req); err != nil {
		logger.Warn("register_validation_failed", slog.Any("error", err))
		return adapters.ErrBadRequest(err.Error())
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

// 2. Login
func (h *AuthHandler) Login(c fiber.Ctx) error {
	logger := application.GetLogger(c.Context())

	var req LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		logger.Warn("login_binding_failed", slog.Any("error", err))
		return adapters.ErrBadRequest(err.Error())
	}

	if err := Validate(req); err != nil {
		logger.Warn("login_validation_failed", slog.Any("error", err))
		return adapters.ErrBadRequest(err.Error())
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

// 3. Refresh Token
func (h *AuthHandler) Refresh(c fiber.Ctx) error {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	var req RefreshRequest
	if err := c.Bind().Body(&req); err != nil {
		logger.Warn("refresh_binding_failed", slog.Any("error", err))
		return adapters.ErrBadRequest(err.Error())
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

// 4. Logout
func (h *AuthHandler) Logout(c fiber.Ctx) error {
	ctx := c.Context()
	logger := application.GetLogger(ctx)

	if !application.IsAuthenticated(ctx) {
		logger.Warn("logout_attempt_unauthenticated")
		return adapters.ErrBadRequest("missing identity context in request")
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
