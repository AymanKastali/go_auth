package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/core/application/apperr"
	"go_auth/internal/core/application/ports/use_cases"

	"github.com/gofiber/fiber/v2"
)

type RefreshTokenHandler struct {
	useCase use_cases.RefreshTokenUseCasePort
}

func NewRefreshTokenHandler(
	uc use_cases.RefreshTokenUseCasePort,
) *RefreshTokenHandler {
	return &RefreshTokenHandler{useCase: uc}
}

func (h *RefreshTokenHandler) Execute(c *fiber.Ctx) error {
	var req dto.RefreshTokenRequest

	// Extract Device ID header
	deviceID := c.Get("X-Device-ID")
	if deviceID == "" {
		return utils.Failure(
			c,
			fiber.StatusBadRequest,
			"Device ID is required",
			"missing device ID",
		)
	}

	// Parse body
	if err := c.BodyParser(&req); err != nil {
		return utils.Failure(
			c,
			fiber.StatusBadRequest,
			"Invalid request body",
			err.Error(),
		)
	}

	// Call use case
	authResp, err := h.useCase.RefreshToken(req.RefreshToken, deviceID)
	if err != nil {
		appErr := apperr.FromDomainError(err)
		switch appErr {
		case apperr.ErrInvalidCredentials, apperr.ErrDeviceNotUsable:
			return utils.Failure(
				c,
				fiber.StatusUnauthorized,
				"Refresh token is invalid or expired",
				appErr.Error(),
			)
		case apperr.ErrDeviceNotFound:
			return utils.Failure(
				c,
				fiber.StatusUnauthorized,
				"Device not found",
				appErr.Error(),
			)
		case apperr.ErrUserInactive:
			return utils.Failure(
				c,
				fiber.StatusForbidden,
				"User is inactive",
				appErr.Error(),
			)
		default:
			return utils.Failure(
				c,
				fiber.StatusInternalServerError,
				"Internal server error",
				appErr.Error(),
			)
		}
	}

	// Success
	response := dto.LoginResponse{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
	}

	return utils.Success(
		c,
		fiber.StatusOK,
		response,
		"User token refreshed successfully",
	)
}
