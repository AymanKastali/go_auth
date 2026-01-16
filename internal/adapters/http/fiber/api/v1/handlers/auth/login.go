package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type LoginHandler struct {
	uc ports.ILoginUseCase
}

func NewLoginHandler(uc ports.ILoginUseCase) *LoginHandler {
	return &LoginHandler{uc: uc}
}

func (h *LoginHandler) Execute(c *fiber.Ctx) error {
	ctx := utils.GetContext(c)
	traceID := ctx.RequestID

	var req dto.LoginRequest

	// 1. Protocol Layer: Syntax check (HTTP 400)
	if err := c.BodyParser(&req); err != nil {
		// Strictly an adapter concern; core is never reached
		return http.NewBadRequest(err)
	}

	// 2. Application Layer: Schema validation (HTTP 422)
	if err := utils.Validate(req); err != nil {
		return http.NewBadRequest(err)
	}

	// 3. Core Execution: Orchestration
	authResp, err := h.uc.Execute(
		traceID,
		req.Email,
		req.Password,
		ctx.DeviceID,
		ctx.DeviceName,
		ctx.UserAgent,
		ctx.IPAddress,
	)
	if err != nil {
		return err
	}

	return utils.OK(c, dto.LoginResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
	}, "authenticated")
}
