package main

import (
	"go_auth/internal/adapters/http/fiberapp"

	"github.com/gofiber/fiber/v3"
)

type handlers struct {
	auth      *fiberapp.AuthHandler
	user      *fiberapp.UserHandler
	policy    *fiberapp.PolicyHandler
	authGuard fiber.Handler
}

func newHandlers(uc useCases) handlers {
	validate := fiberapp.NewValidator()

	return handlers{
		auth: fiberapp.NewAuthHandler(
			validate,
			uc.register,
			uc.login,
			uc.refresh,
			uc.logout,
			uc.validate,
			uc.forgotPassword,
			uc.resetPassword,
		),
		user: fiberapp.NewUserHandler(
			validate,
			uc.findByEmail,
			uc.getByID,
			uc.getMe,
			uc.updateMe,
			uc.changePassword,
		),
		policy:    fiberapp.NewPolicyHandler(uc.publicPolicies),
		authGuard: fiberapp.Protected(uc.validate),
	}
}
