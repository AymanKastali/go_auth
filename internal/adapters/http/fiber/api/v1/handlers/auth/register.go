package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/use_cases"

	"github.com/gofiber/fiber/v2"
)

type RegisterHandler struct {
	uc *use_cases.RegisterUseCase
}

func NewRegisterHandler(uc *use_cases.RegisterUseCase) *RegisterHandler {
	return &RegisterHandler{uc: uc}
}

func (h *RegisterHandler) Execute(c *fiber.Ctx) error {
	var req dto.RegisterRequest

	// 1. TRANSPORT: Parse request body
	if err := c.BodyParser(&req); err != nil {
		// Return a ValidationErr so the Global Handler returns a 400
		return apperr.NewValidationErr(err)
	}

	// 2. APPLICATION: Call the use case
	domainResp, err := h.uc.Register(req.Email, req.Password)
	if err != nil {
		// The Global Error Handler handles the 409 Conflict, 400, etc.
		return err
	}

	// 3. SUCCESS: Map domain response to adapter DTO
	adapterResp := dto.RegisteredUserResponse{
		UserID: domainResp.UserID,
		Email:  domainResp.Email,
	}

	return utils.Created(c, adapterResp, "User registered successfully")
}
