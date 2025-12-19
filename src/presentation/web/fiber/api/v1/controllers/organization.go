package controllers

import (
	"go_auth/src/application/dto"
	"go_auth/src/application/handlers"
	"go_auth/src/presentation/errors"
	"go_auth/src/presentation/web/fiber/dto/request"

	"github.com/gofiber/fiber/v2"
)

type OrganizationController struct {
	listUserOrgsHandler *handlers.ListUserOrganizationsHandler
	registerOrgsHandler *handlers.RegisterOrganizationHandler
}

func NewOrganizationController(
	listHandler *handlers.ListUserOrganizationsHandler,
	registerHandler *handlers.RegisterOrganizationHandler,
) *OrganizationController {
	return &OrganizationController{
		listUserOrgsHandler: listHandler,
		registerOrgsHandler: registerHandler,
	}
}

func (c *OrganizationController) ListUserOrganizations(ctx *fiber.Ctx) error {
	userID := ctx.Locals("userID")
	if userID == nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	orgs, err := c.listUserOrgsHandler.Execute(userID.(string))
	if err != nil {
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	response := make([]*dto.UserOrganizationResponse, len(orgs))
	copy(response, orgs)

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"organizations": response,
	})
}

func (c *OrganizationController) RegisterOrganization(ctx *fiber.Ctx) error {
	userIDRaw := ctx.Locals("userID")
	if userIDRaw == nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthenticated",
		})
	}

	var req request.RegisterOrganizationRequest
	if err := ctx.BodyParser(&req); err != nil {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	result, err := c.registerOrgsHandler.Execute(
		userIDRaw.(string),
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

	return ctx.Status(fiber.StatusCreated).JSON(result)
}
