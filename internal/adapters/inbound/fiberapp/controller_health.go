package fiberapp

import (
	"go_auth/internal/application"

	"github.com/gofiber/fiber/v3"
)

type HealthController struct {
	checker application.IHealthChecker
}

func NewHealthController(checker application.IHealthChecker) *HealthController {
	return &HealthController{checker: checker}
}

func (h *HealthController) RegisterRoutes(app *fiber.App) {
	app.Get("/health", h.Health)
	app.Get("/ready", h.Ready)
}

// @Summary Liveness check
// @Description Returns 200 if the service is alive
// @Tags Health
// @Produce json
// @Success 200 {object} SuccessResponse
// @Router /health [get]
func (h *HealthController) Health(c fiber.Ctx) error {
	return SendOK(c, "ok", nil)
}

// @Summary Readiness check
// @Description Returns 200 if the service is ready to accept traffic, 503 if not
// @Tags Health
// @Produce json
// @Success 200 {object} SuccessResponse
// @Failure 503 {object} ErrorResponse
// @Router /ready [get]
func (h *HealthController) Ready(c fiber.Ctx) error {
	if err := h.checker.Ping(c.Context()); err != nil {
		return SendServiceUnavailable(c, "service is not ready")
	}
	return SendOK(c, "ready", nil)
}
