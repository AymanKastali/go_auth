package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

type RegisterHandler struct {
	uc ports.IRegisterUseCase
}

func NewRegisterHandler(
	uc ports.IRegisterUseCase,
) *RegisterHandler {
	return &RegisterHandler{uc: uc}
}

func (h *RegisterHandler) Execute(c *fiber.Ctx) error {
	reqCtx := utils.ReqCtx(c)
	l := reqCtx.Logger

	var req dto.RegisterRequest

	l.Info("Handling registration request")

	if err := c.BodyParser(&req); err != nil {
		l.Warn("Failed to parse registration request body", slog.Any("error", err))
		return http.NewBadRequest(err)
	}

	l.Debug("Validating registration data", slog.String("email", req.Email))

	if err := utils.Validate(req); err != nil {
		l.Warn("Registration request validation failed",
			slog.String("email", req.Email),
			slog.Any("error", err),
		)
		return http.NewBadRequest(err)
	}

	domainResp, err := h.uc.Execute(c.UserContext(), req.Email, req.Password)
	if err != nil {
		l.Warn("Registration execution failed",
			slog.String("email", req.Email),
			slog.Any("error", err),
		)
		return err
	}

	l.Info("User registered successfully", slog.String("user_id", domainResp.UserID))

	return utils.Created(
		c,
		dto.RegisteredUserResponse{
			UserID: domainResp.UserID,
			Email:  domainResp.Email,
		},
		"user successfully registered",
	)
}
