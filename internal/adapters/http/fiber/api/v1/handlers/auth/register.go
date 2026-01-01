package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
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

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return utils.Failure(
			c,
			fiber.StatusBadRequest,
			"Invalid request body",
			err.Error(),
		)
	}

	// Call the use case
	domainResp, err := h.useCase.Register(req.Email, req.Password)
	if err != nil {
		appErr := apperr.FromDomainError(err)

		switch appErr {
		case apperr.ErrInvalidCredentials:
			return utils.Failure(c, fiber.StatusBadRequest, "Invalid email or password", appErr.Error())
		case apperr.ErrEmailAlreadyRegistered:
			return utils.Failure(c, fiber.StatusConflict, "Email already registered", appErr.Error())
		case apperr.ErrInternal:
			return utils.Failure(c, fiber.StatusInternalServerError, "Internal server error", appErr.Error())
		default:
			return utils.Failure(c, fiber.StatusInternalServerError, "Unexpected error", appErr.Error())
		}
	}

	// Map domain response to adapter DTO
	adapterResp := dto.RegisteredUserResponse{
		UserID: domainResp.UserID,
		Email:  domainResp.Email,
	}

	return utils.Success(c, fiber.StatusCreated, adapterResp, "User registered successfully")
}
