package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type loginHandler struct {
	uc ports.LoginUseCasePort
}

var _ interfaces.ILoginHandler = (*loginHandler)(nil)

func NewLoginHandler(
	uc ports.LoginUseCasePort,
) interfaces.ILoginHandler {
	return &loginHandler{uc: uc}
}

func (h *loginHandler) Execute(c *fiber.Ctx) error {
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
		return apperr.Validation(err)
	}

	// 3️⃣ Call use case
	authResp, err := h.uc.Execute(
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
