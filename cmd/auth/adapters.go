package main

import (
	"log/slog"

	"go_auth/internal/adapters"
	"go_auth/internal/adapters/inbound/fiberapp"
	"go_auth/internal/adapters/outbound"
	"go_auth/internal/adapters/outbound/postgres"
	"go_auth/internal/application"

	"github.com/gofiber/fiber/v3"
)

// outboundAdapters holds driven adapter implementations
// (e.g. persistence, email, transactions, event dispatching, queries).
type outboundAdapters struct {
	persistence *postgres.PersistenceFactory
	emailSvc    application.IEmailService
	txManager   application.ITransactionManager
	dispatcher  application.IEventDispatcher
	userQuery   application.IUserQueryPort
	seedLoader  application.IRoleSeedLoader
}

func newOutboundAdapters(cfg *adapters.Config, logger *slog.Logger) outboundAdapters {
	pf, err := postgres.NewPersistenceFactory(cfg.Database.URL)
	if err != nil {
		panic(err)
	}

	return outboundAdapters{
		persistence: pf,
		emailSvc:    outbound.NewEmailService(cfg.Email),
		txManager:   pf.NewTransactionManager(),
		dispatcher:  outbound.NewLoggingEventDispatcher(logger),
		userQuery:   pf.NewUserQueryAdapter(),
		seedLoader:  outbound.NewYAMLRoleSeedLoader(cfg.Seed.RolesFilePath),
	}
}

// fiberHandlers groups all Fiber-specific HTTP handlers and middleware.
type fiberHandlers struct {
	auth      *fiberapp.AuthHandler
	user      *fiberapp.UserHandler
	policy    *fiberapp.PolicyHandler
	health    *fiberapp.HealthHandler
	admin     *fiberapp.AdminHandler
	authGuard fiber.Handler
}

// inboundAdapters holds driving adapter implementations (HTTP handlers).
type inboundAdapters struct {
	fiber fiberHandlers
}

func newInboundAdapters(uc applicationLayer, out outboundAdapters) inboundAdapters {
	validate := fiberapp.NewValidator()

	return inboundAdapters{
		fiber: fiberHandlers{
			auth: fiberapp.NewAuthHandler(
				validate,
				uc.register,
				uc.login,
				uc.refresh,
				uc.logout,
				uc.validate,
				uc.forgotPassword,
				uc.resetPassword,
				uc.confirmActivation,
				uc.resendActivation,
			),
			user: fiberapp.NewUserHandler(
				validate,
				uc.findByEmail,
				uc.getByID,
				uc.getMe,
				uc.updateMe,
				uc.changePassword,
			),
			policy: fiberapp.NewPolicyHandler(uc.publicPolicies),
			health: fiberapp.NewHealthHandler(out.persistence),
			admin: fiberapp.NewAdminHandler(
				validate,
				uc.listRoles, uc.getRole, uc.createRole,
				uc.assignPermission, uc.revokePermission,
				uc.listUsers, uc.getByID,
				uc.assignUserRole, uc.revokeUserRole,
				uc.adminActivate, uc.adminDeactivate, uc.adminDelete,
				uc.seedRoles, uc.validate,
			),
			authGuard: fiberapp.Protected(uc.validate),
		},
	}
}

func newApp(
	cfg adapters.AppConfig,
	h fiberHandlers,
	baseLogger *slog.Logger,
) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: fiberapp.NewErrorHandler(),
		AppName:      cfg.Name,
	})

	idGen := outbound.NewULIDGenerator()
	fiberapp.ConfigureMiddlewares(app, baseLogger, idGen)
	fiberapp.RegisterRoutes(
		app,
		h.auth,
		h.user,
		h.policy,
		h.health,
		h.admin,
		h.authGuard,
	)
	return app
}
