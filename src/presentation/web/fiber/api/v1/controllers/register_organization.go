package controllers

import (
	usecases "go_auth/src/application/use_cases"
	"go_auth/src/infra/mappers"
	"go_auth/src/presentation/errors"
	"go_auth/src/presentation/web/fiber/dto/request"

	"github.com/gofiber/fiber/v2"
)

type RegisterOrganizationController struct {
	registerOrganizationUseCase *usecases.RegisterOrganizationUseCase
	uuidMapper                  mappers.UUIDMapper
}

func NewRegisterOrganizationController(
	registerOrganizationUseCase *usecases.RegisterOrganizationUseCase,
	uuidMapper mappers.UUIDMapper,
) *RegisterOrganizationController {
	return &RegisterOrganizationController{
		registerOrganizationUseCase: registerOrganizationUseCase,
		uuidMapper:                  uuidMapper,
	}
}

func (c *RegisterOrganizationController) Handle(ctx *fiber.Ctx) error {
	// -------------------------------------------------
	// 1. Authenticated User (from JWT middleware)
	// -------------------------------------------------
	userIDRaw := ctx.Locals("userID")
	if userIDRaw == nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthenticated",
		})
	}

	ownerUserID, err := c.uuidMapper.FromString(userIDRaw.(string))
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "invalid user identity",
		})
	}

	// -------------------------------------------------
	// 2. Parse Request
	// -------------------------------------------------
	var req request.RegisterOrganizationRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// -------------------------------------------------
	// 3. Execute Use Case
	// -------------------------------------------------
	result, err := c.registerOrganizationUseCase.Execute(
		ownerUserID,
		req.Name,
	)

	if err != nil {
		switch err {
		case errors.ErrUnauthorized:
			return ctx.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": err.Error(),
			})
		default:
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
	}

	// -------------------------------------------------
	// 4. Return Response
	// -------------------------------------------------
	return ctx.Status(fiber.StatusCreated).JSON(result)
}
