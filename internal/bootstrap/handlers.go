package bootstrap

import (
	"go_auth/internal/adapters/http/fiberapp"

	"github.com/gofiber/fiber/v3"
)

type Handlers struct {
	Auth      *fiberapp.AuthHandler
	User      *fiberapp.UserHandler
	AuthGuard fiber.Handler
}

func NewHandlers(uc UseCases) Handlers {
	return Handlers{
		Auth: fiberapp.NewAuthHandler(
			uc.Register,
			uc.Login,
			uc.Refresh,
			uc.Logout,
			uc.Validate,
			uc.ResetPassword,
		),
		User: fiberapp.UewUserHandler(
			uc.FindByEmail,
			uc.GetByID,
			uc.GetMe,
			uc.UpdateMe,
			uc.ChangePassword,
		),
		AuthGuard: fiberapp.Protected(uc.Validate),
	}
}
