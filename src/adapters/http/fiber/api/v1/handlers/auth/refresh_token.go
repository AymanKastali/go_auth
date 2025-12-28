package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/adapters/http/fiber/utils"
	"go_auth/src/application/ports/use_cases"
	"go_auth/src/domain/errors"

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

	deviceID := c.Get("X-Device-ID")
	if deviceID == "" {
		return utils.Failure(
			c,
			fiber.StatusBadRequest,
			"Device ID is required",
			errors.ErrInvalidDeviceID,
		)
	}

	if err := c.BodyParser(&req); err != nil {
		return utils.Failure(
			c,
			fiber.StatusBadRequest,
			"Invalid request body",
			err.Error(),
		)
	}

	authResp, err := h.useCase.RefreshToken(req.RefreshToken, deviceID)
	if err != nil {
		switch err {

		case errors.ErrInvalidToken,
			errors.ErrRefreshTokenExpired,
			errors.ErrRefreshTokenRevoked,
			errors.ErrInvalidTokenUser:
			return utils.Failure(
				c,
				fiber.StatusUnauthorized,
				"Refresh token is invalid or expired",
				err.Error(),
			)

		case errors.ErrInvalidDeviceID:
			return utils.Failure(
				c,
				fiber.StatusBadRequest,
				"Invalid device ID",
				err.Error(),
			)

		case errors.ErrUserNotFound:
			return utils.Failure(
				c,
				fiber.StatusNotFound,
				"User not found",
				err.Error(),
			)

		default:
			return utils.Failure(
				c,
				fiber.StatusInternalServerError,
				"Internal server error",
				err.Error(),
			)
		}
	}

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
