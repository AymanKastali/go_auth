package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

type LoginHandler struct {
	uc ports.ILoginUseCase
}

func NewLoginHandler(uc ports.ILoginUseCase) *LoginHandler {
	return &LoginHandler{uc: uc}
}

func (h *LoginHandler) Execute(c *fiber.Ctx) error {
	reqCtx := utils.ReqCtx(c)
	l := reqCtx.Logger

	var req dto.LoginRequest

	l.Info("Handling login request")

	if err := c.BodyParser(&req); err != nil {
		l.Warn("Failed to parse login request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	l.Debug("Validating login credentials", slog.String("email", req.Email))

	if err := utils.Validate(req); err != nil {
		l.Warn("Login request validation failed",
			slog.String("email", req.Email),
			slog.Any("error", err),
		)
		return http.NewBadRequest(err)
	}

	authResp, err := h.uc.Execute(
		c.UserContext(),
		req.Email,
		req.Password,
	)
	if err != nil {
		l.Warn("Login execution failed",
			slog.String("email", req.Email),
			slog.Any("error", err),
		)
		return err
	}

	l.Info("User authenticated successfully", slog.String("email", req.Email))

	return utils.OK(c, dto.LoginResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
	}, "authenticated")
}
