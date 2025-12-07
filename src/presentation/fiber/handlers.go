package fiber

import (
	"context"
	"go_auth/src/application/dto"
	usecases "go_auth/src/application/use_cases"
	"time"

	"github.com/gofiber/fiber/v2"
)

type AuthHandlers struct {
	RegisterUC *usecases.RegisterHandler
	LoginUC    *usecases.LoginHandler
}

func NewAuthHandlers(
	registerUC *usecases.RegisterHandler,
	loginUC *usecases.LoginHandler,
) *AuthHandlers {
	return &AuthHandlers{
		RegisterUC: registerUC,
		LoginUC:    loginUC,
	}
}

// Register endpoint
func (h *AuthHandlers) Register(c *fiber.Ctx) error {
	var req dto.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	_, err := h.RegisterUC.Handle(ctx, req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"status": "ok"})
}

// Login endpoint
func (h *AuthHandlers) Login(c *fiber.Ctx) error {
	var req dto.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	ctx, cancel := context.WithTimeout(c.Context(), 10*time.Second)
	defer cancel()

	resp, err := h.LoginUC.Handle(ctx, req)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(resp)
}
