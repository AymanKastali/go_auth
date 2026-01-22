package utils

import (
	"go_auth/internal/core/application/dto"

	"github.com/gofiber/fiber/v3"
)

func ReqCtx(c fiber.Ctx) *dto.RequestContext {
	return dto.FromContext(c.Context())
}

func AuthCtx(c fiber.Ctx) (*dto.AuthContext, bool) {
	return dto.AuthFromContext(c.Context())
}
