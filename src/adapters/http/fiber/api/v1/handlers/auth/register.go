package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	appErrors "go_auth/src/application/errors"
	"go_auth/src/application/ports/use_cases"

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

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// Call the use case
	domainResp, err := h.useCase.Register(req.Email, req.Password)
	if err != nil {
		switch err {
		case appErrors.ErrInvalidEmail:
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		case appErrors.ErrEmailAlreadyRegistered:
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": err.Error(),
			})
		case appErrors.ErrInternal:
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal server error",
			})
		default:
			// fallback for unexpected errors
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "unexpected error",
			})
		}
	}

	// Map domain response to adapter layer DTO
	adapterResp := dto.RegisteredUserResponse{
		UserID: domainResp.UserID,
		Email:  domainResp.Email,
	}

	// Return JSON response
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"user":    adapterResp,
		"message": "user registered successfully",
	})
}
