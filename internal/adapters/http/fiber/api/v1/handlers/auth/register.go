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
	// 1. Extract TraceID (Required by the new apperr system)
	// We check Locals first, then fall back to the header or a default
	traceID, _ := c.Locals("trace_id").(string)
	if traceID == "" {
		traceID = c.Get("X-Request-ID", "registration-flow")
	}

	var req dto.RegisterRequest

	// 2. TRANSPORT: Parse request body
	if err := c.BodyParser(&req); err != nil {
		// Use BadRequest to ensure a 400 Status Code via Global Handler
		return apperr.BadRequest("invalid request payload", traceID, err)
	}

	// 3. APPLICATION: Call the use case with (traceID, email, password)
	domainResp, err := h.uc.Execute(traceID, req.Email, req.Password)
	if err != nil {
		// Bubbles up apperr.Conflict, apperr.Internal, etc.
		return err
	}

	// 4. SUCCESS: Map application DTO to web DTO
	adapterResp := dto.RegisteredUserResponse{
		UserID: domainResp.UserID,
		Email:  domainResp.Email,
	}

	return utils.Created(c, adapterResp, "User registered successfully")
}
