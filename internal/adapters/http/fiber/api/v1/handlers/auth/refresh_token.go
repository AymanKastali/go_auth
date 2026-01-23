package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

type RefreshTokenHandler struct {
	uc ports.ISessionRenewalUseCase
}

func NewRefreshTokenHandler(uc ports.ISessionRenewalUseCase) *RefreshTokenHandler {
	return &RefreshTokenHandler{uc: uc}
}

// @Summary  refresh token
// @Tags     auth
// @Accept   json
// @Produce  json
// @Param    request  body      object  true  "refresh token"
// @Success  200      {object}  object
// @Failure  401      {string}  string "Invalid Token"
// @Router   /auth/refresh [post]
func (h *RefreshTokenHandler) Execute(c fiber.Ctx) error {
	reqCtx := utils.ReqCtx(c)
	l := reqCtx.Logger

	var req dto.RefreshTokenRequest

	l.Info("Handling token refresh request")

	if err := c.Bind().Body(&req); err != nil {
		l.Warn("Failed to parse refresh token request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	if err := utils.Validate(req); err != nil {
		l.Warn("refresh token request validation failed", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	authResp, err := h.uc.Execute(
		c.Context(),
		req.RefreshToken,
	)
	if err != nil {
		l.Warn("Token rotation execution failed", slog.Any("error", err))
		return err
	}

	l.Info("Tokens rotated successfully")

	return utils.OK(
		c,
		dto.LoginResponse{
			AccessToken:  authResp.SessionToken,
			RefreshToken: authResp.SessionRenewalToken,
		},
		"tokens rotated successfully",
	)
}
