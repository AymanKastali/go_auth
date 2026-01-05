package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports/use_cases"

	"github.com/gofiber/fiber/v2"
)

type LoginHandler struct {
	useCase use_cases.LoginUseCasePort
}

func NewLoginHandler(uc use_cases.LoginUseCasePort) *LoginHandler {
	return &LoginHandler{useCase: uc}
}

func (h *LoginHandler) Login(c *fiber.Ctx) error {
	var req dto.LoginRequest

	// 1️⃣ Extract context (Assuming you keep this utility or move it to a middleware)
	// If ExtractRequestContext returns an error, just return it.
	// The Global Error Handler will catch it.
	ctx, err := utils.ExtractRequestContext(c)
	if err != nil {
		return err
	}

	// 2️⃣ Parse request body
	if err := c.BodyParser(&req); err != nil {
		return apperr.NewBadRequestErr(err.Error())
	}

	// 3️⃣ Call use case
	authResp, err := h.useCase.Login(
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

	return utils.OK(
		c,
		dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
		"User logged in successfully",
	)
}
