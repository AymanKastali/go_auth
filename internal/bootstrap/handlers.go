package bootstrap

import (
	"go_auth/internal/adapters/http/fiberapp"

	"github.com/gofiber/fiber/v3"
)

type Handlers struct {
	Auth      *fiberapp.AuthHandler
	AuthGuard fiber.Handler
}

func SetupHandlers(uc UseCases) Handlers {
	return Handlers{
		Auth: fiberapp.NewAuthHandler(
			uc.Register,
			uc.Login,
			uc.Refresh,
			uc.Logout,
			uc.Validate,
		),
		AuthGuard: fiberapp.Protected(uc.Validate),
	}
}
