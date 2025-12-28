// adapters/http/fiber/utils/request_context.go
package utils

import (
	"go_auth/src/adapters/http/fiber/dto"

	"github.com/gofiber/fiber/v2"
)

func ExtractRequestContext(c *fiber.Ctx) (*dto.RequestContext, error) {
	deviceID := c.Get("X-Device-ID")
	if deviceID == "" {
		return nil, fiber.ErrBadRequest
	}

	return &dto.RequestContext{
		DeviceID:   deviceID,
		DeviceName: c.Get("X-Device-Name"),
		UserAgent:  c.Get("User-Agent"),
		IPAddress:  c.IP(),
	}, nil
}
