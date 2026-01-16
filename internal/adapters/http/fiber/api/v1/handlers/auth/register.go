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
	uc     ports.IRegisterUseCase
	logger *slog.Logger
}

func NewRegisterHandler(
	uc ports.IRegisterUseCase,
	logger *slog.Logger,
) *RegisterHandler {
	return &RegisterHandler{uc: uc, logger: logger}
}

func (h *RegisterHandler) Execute(c *fiber.Ctx) error {
	ctx := utils.GetContext(c)
	traceID := ctx.RequestID

	l := h.logger.With(
		slog.String("trace_id", traceID),
		slog.String("handler", "RegisterHandler"),
	)

	l.Info("registration request received")

	var req dto.RegisterRequest

	if err := c.BodyParser(&req); err != nil {
		return http.NewBadRequest(err)
	}

	if err := utils.Validate(req); err != nil {
		return http.NewBadRequest(err)
	}

	domainResp, err := h.uc.Execute(traceID, req.Email, req.Password)
	if err != nil {
		return err
	}

	l.Info("user registered successfully", slog.String("user_id", domainResp.UserID))

	return utils.Created(
		c,
		dto.RegisteredUserResponse{
			UserID: domainResp.UserID,
			Email:  domainResp.Email,
		},
		"user successfully registered",
	)
}
