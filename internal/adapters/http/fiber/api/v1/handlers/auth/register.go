package auth_handlers

import (
	"go_auth/internal/adapters/adaptererr"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/core/application/ports/use_cases"

	"github.com/gofiber/fiber/v2"
)

type RegisterHandler struct {
	useCase use_cases.RegisterUseCasePort
}

func NewRegisterHandler(uc use_cases.RegisterUseCasePort) *RegisterHandler {
	return &RegisterHandler{useCase: uc}
}

func (h *RegisterHandler) Register(c *fiber.Ctx) error {
	var req dto.RegisterRequest

	// 1. TRANSPORT: Parse request body
	if err := c.BodyParser(&req); err != nil {
		// If body parsing fails, we treat it as an internal adapter error
		// or map it to a standardized bad request response.
		status, payload := adaptererr.Translate(err)
		return c.Status(status).JSON(payload)
	}

	// 2. APPLICATION: Call the use case
	domainResp, err := h.useCase.Register(req.Email, req.Password)
	if err != nil {
		// Handler doesn't care about the error type.
		// It just knows it needs to be translated for the client.
		status, payload := adaptererr.Translate(err)
		return c.Status(status).JSON(payload)
	}

	// 3. SUCCESS: Map domain response to adapter DTO
	adapterResp := dto.RegisteredUserResponse{
		UserID: domainResp.UserID,
		Email:  domainResp.Email,
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"success": true,
		"message": "User registered successfully",
		"data":    adapterResp,
	})
}
