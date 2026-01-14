package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/api/v1/handlers/interfaces"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type registerHandler struct {
	uc ports.RegisterUseCasePort
}

var _ interfaces.IRegisterHandler = (*registerHandler)(nil)

func NewRegisterHandler(
	uc ports.RegisterUseCasePort,
) interfaces.IRegisterHandler {
	return &registerHandler{uc: uc}
}

func (h *registerHandler) Execute(c *fiber.Ctx) error {
	// 1. Extract context (RequestID for correlation)
	ctx := utils.GetContext(c)
	requestID := ctx.RequestID

	var req dto.RegisterRequest

	// 2. TRANSPORT: Parse request body
	if err := c.BodyParser(&req); err != nil {
		// KindInvalid: Maps to 400 Bad Request in the Global Error Handler
		return apperr.Invalid("invalid registration request format", requestID, err)
	}

	// 3. Structural Validation (e.g., checking field length, required fields)
	if err := utils.Validate(req); err != nil {
		// KindInvalid: Ensures the DTO matches our API contract
		return apperr.Invalid("validation failed", requestID, err)
	}

	// 4. APPLICATION: Execute registration logic
	domainResp, err := h.uc.Execute(requestID, req.Email, req.Password)
	if err != nil {
		// Propagates KindConflict (if email exists) or KindInternal
		return err
	}

	// 5. SUCCESS: Map application DTO to web response
	adapterResp := dto.RegisteredUserResponse{
		UserID: domainResp.UserID,
		Email:  domainResp.Email,
	}

	// Returns 201 Created
	return utils.Created(c, adapterResp, "User registered successfully")
}
