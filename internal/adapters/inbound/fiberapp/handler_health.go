package fiberapp

import (
	"go_auth/internal/application"

	"github.com/gofiber/fiber/v3"
)

type HealthHandler struct {
	checker application.IHealthChecker
}

func NewHealthHandler(checker application.IHealthChecker) *HealthHandler {
	return &HealthHandler{checker: checker}
}

// @Summary Liveness check
// @Description Returns 200 if the service is alive
// @Tags Health
// @Produce json
// @Success 200 {object} SuccessResponse
// @Router /health [get]
func (h *HealthHandler) Health(c fiber.Ctx) error {
	return SendOK(c, "ok", nil)
}

// @Summary Readiness check
// @Description Returns 200 if the service is ready to accept traffic, 503 if not
// @Tags Health
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 503 {object} ErrorResponse
// @Router /ready [get]
func (h *HealthHandler) Ready(c fiber.Ctx) error {
	if err := h.checker.Ping(c.Context()); err != nil {
		return SendServiceUnavailable(c, "service is not ready")
	}
	return SendOK(c, "ready", nil)
}
