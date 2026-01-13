package utils

import (
	"go_auth/internal/adapters/http/fiber/dto"
	"go_auth/internal/core/application/apperr"

	"github.com/gofiber/fiber/v2"
)

func ExtractRequestContext(c *fiber.Ctx) (*dto.RequestContext, error) {
	// 1. Get the TraceID (RequestID) from context or headers
	// This is required to satisfy the apperr factory methods
	traceID, _ := c.Locals("trace_id").(string)
	if traceID == "" {
		traceID = c.Get("X-Request-ID", "unknown-request")
	}

	// 2. Transport Validation: Device ID is mandatory for session management
	deviceID := c.Get("X-Device-ID")
	if deviceID == "" {
		// Use BadRequest instead of the old Validation method
		return nil, apperr.BadRequest("X-Device-ID header is required", traceID, nil)
	}

	return &dto.RequestContext{
		TraceID:    traceID, // Including traceID in the DTO is helpful for use cases
		DeviceID:   deviceID,
		DeviceName: c.Get("X-Device-Name"),
		UserAgent:  c.Get("User-Agent"),
		IPAddress:  c.IP(),
	}, nil
}
