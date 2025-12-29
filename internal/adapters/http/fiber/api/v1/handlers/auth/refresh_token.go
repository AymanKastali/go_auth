package auth_handlers

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/adapters/http/fiber/utils"
	"go_auth/internal/application/ports/use_cases"
	"go_auth/internal/domain/domainerr"

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
			domainerr.ErrInvalidDeviceID,
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

		case domainerr.ErrInvalidToken,
			domainerr.ErrRefreshTokenExpired,
			domainerr.ErrRefreshTokenRevoked,
			domainerr.ErrInvalidTokenUser:
			return utils.Failure(
				c,
				fiber.StatusUnauthorized,
				"Refresh token is invalid or expired",
				err.Error(),
			)

		case domainerr.ErrInvalidDeviceID:
			return utils.Failure(
				c,
				fiber.StatusBadRequest,
				"Invalid device ID",
				err.Error(),
			)

		case domainerr.ErrUserNotFound:
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
