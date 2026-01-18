package utils

import (
	"go_auth/internal/core/application/dto"
	"log/slog"

	"github.com/gofiber/fiber/v2"
)

func GetReqCtx(c *fiber.Ctx) *dto.RequestContext {
	val := dto.Extract(c.UserContext())

	switch t := val.(type) {
	case *dto.AuthContext:
		return t.RequestContext
	case *dto.RequestContext:
		return t
	default:
		// Fallback to prevent nil pointer panics
		return &dto.RequestContext{RequestID: "unknown", Logger: slog.Default()}
	}
}

// GetAuthCtx returns the full AuthContext only if authenticated
func GetAuthCtx(c *fiber.Ctx) (*dto.AuthContext, bool) {
	auth, ok := dto.Extract(c.UserContext()).(*dto.AuthContext)
	return auth, ok
}
