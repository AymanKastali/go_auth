package utils

import (
	"go_auth/internal/adapters/http/fiber/dto"

	"github.com/gofiber/fiber/v2"
)

// GetContext returns the RequestContext fields regardless of whether the user is authed or not.
func GetContext(c *fiber.Ctx) *dto.RequestContext {
	val := c.Locals(dto.ContextKey)

	// Check if it's already an AuthContext (which contains RequestContext)
	if auth, ok := val.(*dto.AuthContext); ok {
		return &auth.RequestContext
	}

	// Check if it's just a basic RequestContext
	if req, ok := val.(*dto.RequestContext); ok {
		return req
	}

	return &dto.RequestContext{RequestID: "system"}
}

// GetAuthContext returns the full AuthContext. Use this in protected handlers.
func GetAuthContext(c *fiber.Ctx) (*dto.AuthContext, bool) {
	val := c.Locals(dto.ContextKey)
	auth, ok := val.(*dto.AuthContext)
	return auth, ok
}

// SetContext (Initial seeding for public info)
func SetContext(c *fiber.Ctx) *dto.RequestContext {
	reqCtx := &dto.RequestContext{
		RequestID:  c.Get("X-Request-ID", c.Locals("requestid").(string)),
		DeviceID:   c.Get("X-Device-ID"),
		DeviceName: c.Get("X-Device-Name"),
		UserAgent:  c.Get("User-Agent"),
		IPAddress:  c.IP(),
	}
	c.Locals(dto.ContextKey, reqCtx)
	return reqCtx
}
