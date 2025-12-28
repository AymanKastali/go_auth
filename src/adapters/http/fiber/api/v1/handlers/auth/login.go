package auth_handlers

import (
	"go_auth/src/adapters/http/fiber/dto"
	"go_auth/src/adapters/http/fiber/utils"
	"go_auth/src/application/ports/use_cases"
	"go_auth/src/domain/errors"

	"github.com/gofiber/fiber/v2"
)

type LoginHandler struct {
	useCase use_cases.LoginUseCasePort
}

func NewLoginHandler(
	uc use_cases.LoginUseCasePort,
) *LoginHandler {
	return &LoginHandler{useCase: uc}
}

func (h *LoginHandler) Login(c *fiber.Ctx) error {
	var req dto.LoginRequest

	ctx, err := utils.ExtractRequestContext(c)
	if err != nil {
		return utils.Failure(
			c,
			fiber.StatusBadRequest,
			"Device ID is required",
			err.Error(),
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

	authResp, err := h.useCase.Login(
		req.Email,
		req.Password,
		ctx.DeviceID,
		ctx.DeviceName,
		ctx.UserAgent,
		ctx.IPAddress,
	)
	if err != nil {
		switch err {
		case errors.ErrInvalidCredentials:
			return utils.Failure(
				c,
				fiber.StatusUnauthorized,
				"Invalid credentials",
				err.Error(),
			)
		case errors.ErrUserNotMemberOfOrganization:
			return utils.Failure(
				c,
				fiber.StatusBadRequest,
				"Bad request",
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

	return utils.Success(
		c,
		fiber.StatusOK,
		dto.LoginResponse{
			AccessToken:  authResp.AccessToken,
			RefreshToken: authResp.RefreshToken,
		},
		"User logged in successfully",
	)
}
