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

	// 1. Extract context (Now containing TraceID from previous refactor)
	ctx := utils.GetContext(c)

	// 2. Parse request body
	if err := c.BodyParser(&req); err != nil {
		return apperr.BadRequest("invalid login request format", ctx.RequestID, err)
	}

	// 3. Call use case with TraceID and all required identity parameters
	// This matches the updated Execute(string, string, ...) signature
	authResp, err := h.uc.Execute(
		ctx.RequestID,
		req.Email,
		req.Password,
		ctx.DeviceID,
		ctx.DeviceName,
		ctx.UserAgent,
		ctx.IPAddress,
	)
	if err != nil {
		// Bubbles up apperr.Unauthorized (invalid creds) or apperr.Internal
		return err
	}

	// 4. Success Response
	return utils.OK(
		c,
		dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
		"User logged in successfully",
	)
}
