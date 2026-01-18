package utils

import (
	"go_auth/internal/core/application/dto"

	"github.com/gofiber/fiber/v2"
)

func ReqCtx(c *fiber.Ctx) *dto.RequestContext {
	return dto.FromContext(c.UserContext())
}

func AuthCtx(c *fiber.Ctx) (*dto.AuthContext, bool) {
	return dto.AuthFromContext(c.UserContext())
}
