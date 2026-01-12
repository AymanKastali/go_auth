package utils

import (
	"errors"
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/core/application/apperr"

	"github.com/gofiber/fiber/v2"
)

func ExtractRequestContext(c *fiber.Ctx) (*dto.RequestContext, error) {
	deviceID := c.Get("X-Device-ID")
	if deviceID == "" {
		return nil, apperr.Validation(errors.New("X-Device-ID header is required"))
	}

	return &dto.RequestContext{
		DeviceID:   deviceID,
		DeviceName: c.Get("X-Device-Name"),
		UserAgent:  c.Get("User-Agent"),
		IPAddress:  c.IP(),
	}, nil
}
