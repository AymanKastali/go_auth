package auth

import (
	"go_auth/internal/adapters/http"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/ports"

	"github.com/gofiber/fiber/v2"
)

type registerHandler struct {
	uc ports.IRegisterUseCase
}

func NewRegisterHandler(uc ports.IRegisterUseCase) *registerHandler {
	return &registerHandler{uc: uc}
}

func (h *registerHandler) Execute(c *fiber.Ctx) error {
	// 1. Context Acquisition
	ctx := utils.GetContext(c)
	traceID := ctx.RequestID

	var req dto.RegisterRequest

	// 2. Protocol Layer: Syntax Check (HTTP 400)
	if err := c.BodyParser(&req); err != nil {
		// Strictly an infrastructure concern
		return http.NewBadRequest(err)
	}

	// 3. Application Layer: Schema Validation (HTTP 422)
	if err := utils.Validate(req); err != nil {
		return http.NewBadRequest(err)
	}

	// 4. Core Execution: Business Logic
	// The UC handles hashing, checking email uniqueness, and persistence
	domainResp, err := h.uc.Execute(traceID, req.Email, req.Password)
	if err != nil {
		// Propagates apperr.TypeConflict (409) or TypeInternal (500)
		return err
	}

	// 5. Success Presentation (HTTP 201 Created)
	return utils.Created(
		c,
		dto.RegisteredUserResponse{
			UserID: domainResp.UserID,
			Email:  domainResp.Email,
		},
		"user successfully registered",
	)
}
