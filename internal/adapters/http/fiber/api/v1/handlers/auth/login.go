package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr" // Now using the Kind-based apperr
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type loginHandler struct {
	uc ports.ILoginUseCase
}

var _ interfaces.ILoginHandler = (*loginHandler)(nil)

func NewLoginHandler(
	uc ports.ILoginUseCase,
) interfaces.ILoginHandler {
	return &loginHandler{uc: uc}
}

func (h *loginHandler) Execute(c *fiber.Ctx) error {
	var req dto.LoginRequest

	// 1. Extract context (RequestID, DeviceID, etc.)
	ctx := utils.GetContext(c)
	requestID := ctx.RequestID

	// 2. Parse request body
	if err := c.BodyParser(&req); err != nil {
		// FIX: Replaced BadRequest with apperr.Invalid (KindInvalid)
		return apperr.Invalid("invalid login request format", requestID, err)
	}

	// 3. Request Validation
	if err := utils.Validate(req); err != nil {
		// Validation errors are logically 'Invalid' kinds at the app level
		return apperr.Invalid("validation failed", requestID, err)
	}

	// 4. Call use case
	// The use case now returns apperr.AppError with KindUnauthenticated, KindInternal, etc.
	authResp, err := h.uc.Execute(
		requestID,
		req.Email,
		req.Password,
		ctx.DeviceID,
		ctx.DeviceName,
		ctx.UserAgent,
		ctx.IPAddress,
	)
	if err != nil {
		// Just return the error; the GlobalErrorHandler will map the Kind to HTTP status
		return err
	}

	// 5. Success Response
	return utils.OK(
		c,
		dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
		"User logged in successfully",
	)
}
